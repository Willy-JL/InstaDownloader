import os
import re
import sys
import json
import time
import atexit
import pickle
import random
import getpass
import hashlib
import platform
import tempfile
import textwrap
import requests
import urllib.parse
import requests.utils
from functools import partial
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional


@atexit.register
def exit_handler():
    if worker.is_logged_in():
        worker.log("Saving session for %s." % username)
        worker.save_session_to_file(username)


def default_user_agent() -> str:
    return config["user_agent"]


def copy_session(session: requests.Session, request_timeout: Optional[float] = None) -> requests.Session:
    new = requests.Session()
    new.cookies = requests.utils.cookiejar_from_dict(requests.utils.dict_from_cookiejar(session.cookies))
    new.headers = session.headers.copy()
    if request_timeout is not None:
        # Override default timeout behavior.
        # Need to silence mypy bug for this. See: https://github.com/python/mypy/issues/2427
        new.request = partial(new.request, timeout=request_timeout)  # type: ignore
    return new


class InstaDownloader:
    def __init__(self, sleep: bool = True, quiet: bool = False, user_agent: Optional[str] = None,
                 max_connection_attempts: int = 3, request_timeout: Optional[float] = None,
                 rate_controller: Optional[Callable[["InstaDownloader"], "RateController"]] = None):

        self.user_agent = user_agent if user_agent is not None else default_user_agent()
        self.username = None
        self.request_timeout = request_timeout
        self._session = self.get_anonymous_session()
        self.sleep = sleep
        self.quiet = quiet
        self.max_connection_attempts = max_connection_attempts
        self._graphql_page_length = 50
        self._root_rhx_gis = None
        self.two_factor_auth_pending = None

        # error log, filled with error() and printed at the end of Instaloader.main()
        self.error_log = []  # type: List[str]

        self._rate_controller = rate_controller(self) if rate_controller is not None else RateController(self)

        # Can be set to True for testing, disables supression of InstaloaderContext._error_catcher
        self.raise_all_errors = False

        # Cache profile from id (mapping from id to Profile)
        self.profile_id_cache = dict()  # type: Dict[int, Any]

    def log(self, *msg, sep='', end='\n', flush=False):
        with open('log.txt', 'a') as log:
            log.write('[{:%d/%m/%Y - %H:%M:%S}]  {}'.format(datetime.now(), *msg))
            log.write('\n')
        if not self.quiet:
            print('[{:%d/%m/%Y - %H:%M:%S}]  {}'.format(datetime.now(), *msg), sep=sep, end=end, flush=flush)

    def error(self, msg, repeat_at_end=True):
        """Log a non-fatal error message to stderr, which is repeated at program termination.

        :param msg: Message to be printed.
        :param repeat_at_end: Set to false if the message should be printed, but not repeated at program termination."""
        print(msg, file=sys.stderr)
        if repeat_at_end:
            self.error_log.append(msg)

    def save_session_to_file(self, name):
        assert self.username is not None
        filename = "sessions\\{}.session".format(name)
        with open(filename, 'wb') as sessionfile:
            os.chmod(filename, 0o600)
            pickle.dump(requests.utils.dict_from_cookiejar(self._session.cookies), sessionfile)
            self.log("Saved session to %s." % filename)

    def load_session_from_file(self, name):
        filename = "sessions\\{}.session".format(name)
        with open(filename, 'rb') as sessionfile:
            session = requests.Session()
            session.cookies = requests.utils.cookiejar_from_dict(pickle.load(sessionfile))
            session.headers.update(self._default_http_header())
            session.headers.update({'X-CSRFToken': session.cookies.get_dict()['csrftoken']})
            if self.request_timeout is not None:
                session.request = partial(session.request, timeout=self.request_timeout)  # type: ignore
            self._session = session
            self.username = username
            self.log("Loaded session from %s." % filename)

    def test_login(self) -> Optional[str]:
        data = self.graphql_query("d6f4427fbe92d846298cf93df0b937d3", {})
        return data["data"]["user"]["username"] if data["data"]["user"] is not None else None

    def is_logged_in(self) -> bool:
        return bool(self.username)

    def login(self, user, passwd):
        import http.client
        http.client._MAXHEADERS = 200
        session = requests.Session()
        session.cookies.update({'sessionid': '', 'mid': '', 'ig_pr': '1',
                                'ig_vw': '1920', 'ig_cb': '1', 'csrftoken': '',
                                's_network': '', 'ds_user_id': ''})
        session.headers.update(self._default_http_header())
        session.get(config["urls"]["_mid"])
        csrf_token = session.cookies.get_dict()['csrftoken']
        session.headers.update({'X-CSRFToken': csrf_token})
        self.do_sleep()
        enc_password = '#PWD_INSTAGRAM_BROWSER:0:{}:{}'.format(int(datetime.now().timestamp()), passwd)
        login = session.post(config["urls"]["login"],
                             data={'enc_password': enc_password, 'username': user}, allow_redirects=True)
        try:
            resp_json = login.json()
        except json.decoder.JSONDecodeError:
            raise ConnectionException("Login error: JSON decode fail, {} - {}.".format(login.status_code, login.reason))
        if resp_json.get('two_factor_required'):
            two_factor_session = copy_session(session, self.request_timeout)
            two_factor_session.headers.update({'X-CSRFToken': csrf_token})
            two_factor_session.cookies.update({'csrftoken': csrf_token})
            self.two_factor_auth_pending = (two_factor_session,
                                            user,
                                            resp_json['two_factor_info']['two_factor_identifier'])
            raise TwoFactorAuthRequiredException("Login error: two-factor authentication required.")
        if resp_json.get('checkpoint_url'):
            raise ConnectionException("Login: Checkpoint required. Point your browser to "
                                      "https://www.instagram.com{} - "
                                      "follow the instructions, then retry.".format(resp_json.get('checkpoint_url')))
        if resp_json['status'] != 'ok':
            if 'message' in resp_json:
                raise ConnectionException("Login error: \"{}\" status, message \"{}\".".format(resp_json['status'],
                                                                                               resp_json['message']))
            else:
                raise ConnectionException("Login error: \"{}\" status.".format(resp_json['status']))
        if 'authenticated' not in resp_json:
            # Issue #472
            if 'message' in resp_json:
                raise ConnectionException("Login error: Unexpected response, \"{}\".".format(resp_json['message']))
            else:
                raise ConnectionException("Login error: Unexpected response, this might indicate a blocked IP.")
        if not resp_json['authenticated']:
            if resp_json['user']:
                # '{"authenticated": false, "user": true, "status": "ok"}'
                raise BadCredentialsException('Login error: Wrong password.')
            else:
                # '{"authenticated": false, "user": false, "status": "ok"}'
                raise InvalidArgumentException('Login error: User {} does not exist.'.format(user))
        # '{"authenticated": true, "user": true, "userId": ..., "oneTapPrompt": false, "status": "ok"}'
        session.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
        self._session = session
        self.username = user

    def setup_session(self, sessionname):
        if username is not None:
            try:
                self.load_session_from_file(sessionname)
            except FileNotFoundError:
                if self == worker:
                    self.log("Session file does not exist yet - Logging in.")
                else:
                    self.log("Session file does not exist yet - Copying data from main session.")
            if not self.is_logged_in() or username != self.test_login():
                if self == worker:
                    if password is not None:
                        try:
                            self.login(username, password)
                        except TwoFactorAuthRequiredException:
                            while True:
                                try:
                                    code = input("Enter 2FA verification code: ")
                                    self.two_factor_login(code)
                                    break
                                except BadCredentialsException:
                                    pass
                    else:
                        self.log('Please provide a password!')
                        exit()
                else:
                    self._session = copy_session(worker._session)
                    self.username = username
            else:
                self.username = username

    def _default_http_header(self, empty_session_only: bool = False):
        header = {'Accept-Encoding': 'gzip, deflate, br',
                  'Accept-Language': 'en-US,en;q=0.9',
                  'Connection': 'keep-alive',
                  'Content-Length': '0',
                  'Host': 'www.instagram.com',
                  'Origin': 'https://www.instagram.com',
                  'Referer': 'https://www.instagram.com/',
                  'User-Agent': self.user_agent,
                  'X-Instagram-AJAX': '1',
                  'X-Requested-With': 'XMLHttpRequest'}
        if empty_session_only:
            del header['Host']
            del header['Origin']
            del header['Referer']
            del header['X-Instagram-AJAX']
            del header['X-Requested-With']
        return header

    def two_factor_login(self, two_factor_code):
        """Second step of login if 2FA is enabled."""
        if not self.two_factor_auth_pending:
            raise InvalidArgumentException("No two-factor authentication pending.")
        (session, user, two_factor_id) = self.two_factor_auth_pending

        login = session.post(config["urls"]["2fa_login"],
                             data={'username': user, 'verificationCode': two_factor_code, 'identifier': two_factor_id},
                             allow_redirects=True)
        resp_json = login.json()
        if resp_json['status'] != 'ok':
            if 'message' in resp_json:
                raise BadCredentialsException("Login error: {}".format(resp_json['message']))
            else:
                raise BadCredentialsException("Login error: \"{}\" status.".format(resp_json['status']))
        session.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
        self._session = session
        self.username = user
        self.two_factor_auth_pending = None

    def do_sleep(self):
        """Sleep a short time if self.sleep is set. Called before each request to instagram.com."""
        if self.sleep:
            time.sleep(min(random.expovariate(0.7), 5.0))

    def get_json(self, path: str, params: Dict[str, Any], host: str = 'www.instagram.com',
                 session: Optional[requests.Session] = None, _attempt=1) -> Dict[str, Any]:
        """JSON request to Instagram.

        :param _attempt:
        :param path: URL, relative to the given domain which defaults to www.instagram.com/
        :param params: GET parameters
        :param host: Domain part of the URL from where to download the requested JSON; defaults to www.instagram.com
        :param session: Session to use, or None to use self.session
        :return: Decoded response dictionary
        :raises QueryReturnedBadRequestException: When the server responds with a 400.
        :raises QueryReturnedNotFoundException: When the server responds with a 404.
        :raises ConnectionException: When query repeatedly failed.
        """
        is_graphql_query = 'query_hash' in params and 'graphql/query' in path
        is_iphone_query = host == 'i.instagram.com'
        is_other_query = not is_graphql_query and host == "www.instagram.com"
        sess = session if session else self._session
        try:
            self.do_sleep()
            if is_graphql_query:
                self._rate_controller.wait_before_query(params['query_hash'])
            if is_iphone_query:
                self._rate_controller.wait_before_query('iphone')
            if is_other_query:
                self._rate_controller.wait_before_query('other')
            resp = sess.get('https://{0}/{1}'.format(host, path), params=params, allow_redirects=False)
            while resp.is_redirect:
                redirect_url = resp.headers['location']
                self.log('\nHTTP redirect from https://{0}/{1} to {2}'.format(host, path, redirect_url))
                if redirect_url.startswith('https://www.instagram.com/accounts/login'):
                    # alternate rate limit exceeded behavior
                    raise TooManyRequestsException("429 Too Many Requests: redirected to login")
                if redirect_url.startswith('https://{}/'.format(host)):
                    resp = sess.get(redirect_url if redirect_url.endswith('/') else redirect_url + '/',
                                    params=params, allow_redirects=False)
                else:
                    break
            if resp.status_code == 400:
                raise QueryReturnedBadRequestException("400 Bad Request")
            if resp.status_code == 404:
                raise QueryReturnedNotFoundException("404 Not Found")
            if resp.status_code == 429:
                raise TooManyRequestsException("429 Too Many Requests")
            if resp.status_code != 200:
                raise ConnectionException("HTTP error code {}.".format(resp.status_code))
            is_html_query = not is_graphql_query and not "__a" in params and host == "www.instagram.com"
            if is_html_query:
                match = re.search(r'window\._sharedData = (.*);</script>', resp.text)
                if match is None:
                    raise QueryReturnedNotFoundException("Could not find \"window._sharedData\" in html response.")
                resp_json = json.loads(match.group(1))
                entry_data = resp_json.get('entry_data')
                post_or_profile_page = list(entry_data.values())[0] if entry_data is not None else None
                if post_or_profile_page is None:
                    raise ConnectionException("\"window._sharedData\" does not contain required keys.")
                # If GraphQL data is missing in `window._sharedData`, search for it in `__additionalDataLoaded`.
                if 'graphql' not in post_or_profile_page[0]:
                    match = re.search(r'window\.__additionalDataLoaded\([^{]+{"graphql":({.*})}\);</script>',
                                      resp.text)
                    if match is not None:
                        post_or_profile_page[0]['graphql'] = json.loads(match.group(1))
                return resp_json
            else:
                resp_json = resp.json()
            if 'status' in resp_json and resp_json['status'] != "ok":
                if 'message' in resp_json:
                    raise ConnectionException("Returned \"{}\" status, message \"{}\".".format(resp_json['status'],
                                                                                               resp_json['message']))
                else:
                    raise ConnectionException("Returned \"{}\" status.".format(resp_json['status']))
            return resp_json
        except (ConnectionException, json.decoder.JSONDecodeError, requests.exceptions.RequestException) as err:
            error_string = "JSON Query to {}: {}".format(path, err)
            if _attempt == self.max_connection_attempts:
                if isinstance(err, QueryReturnedNotFoundException):
                    raise QueryReturnedNotFoundException(error_string) from err
                else:
                    raise ConnectionException(error_string) from err
            self.error(error_string + " [retrying; skip with ^C]", repeat_at_end=False)
            try:
                if isinstance(err, TooManyRequestsException):
                    if is_graphql_query:
                        self._rate_controller.handle_429(params['query_hash'])
                    if is_iphone_query:
                        self._rate_controller.handle_429('iphone')
                    if is_other_query:
                        self._rate_controller.handle_429('other')
                return self.get_json(path=path, params=params, host=host, session=sess, _attempt=_attempt + 1)
            except KeyboardInterrupt:
                self.error("[skipped by user]", repeat_at_end=False)
                raise ConnectionException(error_string) from err

    def get_anonymous_session(self) -> requests.Session:
        """Returns our default anonymous requests.Session object."""
        session = requests.Session()
        session.cookies.update({'sessionid': '', 'mid': '', 'ig_pr': '1',
                                'ig_vw': '1920', 'csrftoken': '',
                                's_network': '', 'ds_user_id': ''})
        session.headers.update(self._default_http_header(empty_session_only=True))
        if self.request_timeout is not None:
            session.request = partial(session.request, timeout=self.request_timeout)  # type: ignore
        return session

    def graphql_query(self, query_hash: str, variables: Dict[str, Any],
                      referer: Optional[str] = None, rhx_gis: Optional[str] = None) -> Dict[str, Any]:
        """
        Do a GraphQL Query.

        :param query_hash: Query identifying hash.
        :param variables: Variables for the Query.
        :param referer: HTTP Referer, or None.
        :param rhx_gis: 'rhx_gis' variable as somewhere returned by Instagram, needed to 'sign' request
        :return: The server's response dictionary.
        """
        with copy_session(self._session, self.request_timeout) as tmpsession:
            tmpsession.headers.update(self._default_http_header(empty_session_only=True))
            del tmpsession.headers['Connection']
            del tmpsession.headers['Content-Length']
            tmpsession.headers['authority'] = 'www.instagram.com'
            tmpsession.headers['scheme'] = 'https'
            tmpsession.headers['accept'] = '*/*'
            if referer is not None:
                tmpsession.headers['referer'] = urllib.parse.quote(referer)

            variables_json = json.dumps(variables, separators=(',', ':'))

            if rhx_gis:
                # self.log("rhx_gis {} query_hash {}".format(rhx_gis, query_hash))
                values = "{}:{}".format(rhx_gis, variables_json)
                x_instagram_gis = hashlib.md5(values.encode()).hexdigest()
                tmpsession.headers['x-instagram-gis'] = x_instagram_gis

            resp_json = self.get_json('graphql/query',
                                      params={'query_hash': query_hash,
                                              'variables': variables_json},
                                      session=tmpsession)
        if 'status' not in resp_json:
            self.error("GraphQL response did not contain a \"status\" field.")
        return resp_json

    @property
    def session(self):
        return self._session

    def main(self):
        self._session.headers.update({'host': None,
                                      'sec-fetch-dest': 'empty',
                                      'sec-fetch-mode': 'cors',
                                      'sec-fetch-site': 'same-site',
                                      'x-ig-app-id': '1217981644879628',
                                      'x-ig-www-claim': 'hmac.AR12vyN6Dx6fOn4XsPl-LmkVZPgwUDD7dz-Q3dDNKmDERqFV'})
        while self.handle_inbox():
            time.sleep(120)

    def handle_inbox(self):
        r = self._session.get(config["urls"]["inbox"], params={'persistentBadging': True, 'folder': None,
                                                               'limit': 20, 'thread_message_limit': 10})
        inbox = json.loads(r.text)
        if inbox["inbox"]["unseen_count"] != 0:
            return self.handle_unreads(inbox["inbox"]["threads"])
        return True

    def handle_unreads(self, threads):
        for thread in threads:
            last_msg = thread["items"][0]
            sender_id = last_msg["user_id"]
            if sender_id != config["bot_user_id"]:
                thread_title = thread["thread_title"]
                if not self.handle_message(last_msg, thread_title):
                    return False
        return True

    def handle_message(self, msg, thread_title):
        item_type = msg["item_type"]
        if item_type == 'media_share':  # Photo / video/ carousel post
            pass
        elif item_type == 'clip':  # Reels post
            pass
        elif item_type == 'story_share':  # Photo / video story
            pass
        elif item_type == 'felix_share':  # IGTV post
            pass
        elif item_type == 'text' and thread_title in config["admin_usernames"]:  # Admin text message
            text = msg["text"].lower()
            prefix = config["admin_command_prefix"]
            if text.startswith(prefix):
                command = text[len(prefix):]
                return self.handle_admin_command(command)
        return True

    def handle_admin_command(self, command):
        if command == 'shutdown':
            self.log('Received shutdown command, shutting down...')
            return False
        return True


class InstaDownloaderException(Exception):
    pass


class ConnectionException(InstaDownloaderException):
    pass


class BadCredentialsException(InstaDownloaderException):
    pass


class InvalidArgumentException(InstaDownloaderException):
    pass


class TwoFactorAuthRequiredException(InstaDownloaderException):
    pass


class QueryReturnedNotFoundException(ConnectionException):
    pass


class QueryReturnedBadRequestException(InstaDownloaderException):
    pass


class TooManyRequestsException(ConnectionException):
    pass


class RateController:
    """
    Class providing request tracking and rate controlling to stay within rate limits.
    """

    def __init__(self, context: InstaDownloader):
        self._context = context
        self._graphql_query_timestamps = dict()  # type: Dict[str, List[float]]
        self._graphql_earliest_next_request_time = 0.0

    def sleep(self, secs: float):
        """Wait given number of seconds."""
        # Not static, to allow for the behavior of this method to depend on context-inherent properties, such as
        # whether we are logged in.
        # pylint:disable=no-self-use
        time.sleep(secs)

    def _dump_query_timestamps(self, current_time: float, failed_query_type: str):
        windows = [10, 11, 15, 20, 30, 60]
        self._context.error("Requests within last {} minutes grouped by type:"
                            .format('/'.join(str(w) for w in windows)),
                            repeat_at_end=False)
        for query_type, times in self._graphql_query_timestamps.items():
            reqs_in_sliding_window = [sum(t > current_time - w * 60 for t in times) for w in windows]
            self._context.error(" {} {:>32}: {}".format(
                "*" if query_type == failed_query_type else " ",
                query_type,
                " ".join("{:4}".format(reqs) for reqs in reqs_in_sliding_window)
            ), repeat_at_end=False)

    def count_per_sliding_window(self, query_type: str) -> int:
        """Return how many GraphQL requests can be done within the sliding window."""
        # Not static, to allow for the count_per_sliding_window to depend on context-inherent properties, such as
        # whether we are logged in.
        # pylint:disable=no-self-use,unused-argument
        return 200

    def query_waittime(self, query_type: str, current_time: float, untracked_queries: bool = False) -> float:
        """Calculate time needed to wait before GraphQL query can be executed."""
        sliding_window = 660
        if query_type not in self._graphql_query_timestamps:
            self._graphql_query_timestamps[query_type] = []
        self._graphql_query_timestamps[query_type] = list(filter(lambda t: t > current_time - 60 * 60,
                                                                 self._graphql_query_timestamps[query_type]))
        reqs_in_sliding_window = list(filter(lambda t: t > current_time - sliding_window,
                                             self._graphql_query_timestamps[query_type]))
        count_per_sliding_window = self.count_per_sliding_window(query_type)
        if len(reqs_in_sliding_window) < count_per_sliding_window and not untracked_queries:
            return max(0.0, self._graphql_earliest_next_request_time - current_time)
        next_request_time = min(reqs_in_sliding_window) + sliding_window + 6
        if untracked_queries:
            self._graphql_earliest_next_request_time = next_request_time
        return max(next_request_time, self._graphql_earliest_next_request_time) - current_time

    def wait_before_query(self, query_type: str) -> None:
        """This method is called before a query to Instagram. It calls :meth:`RateController.sleep` to wait
        until the request can be made."""
        waittime = self.query_waittime(query_type, time.monotonic(), False)
        assert waittime >= 0
        if waittime > 15:
            self._context.log("\nToo many queries in the last time. Need to wait {} seconds, until {:%H:%M}."
                              .format(round(waittime), datetime.now() + timedelta(seconds=waittime)))
        if waittime > 0:
            self.sleep(waittime)
        if query_type not in self._graphql_query_timestamps:
            self._graphql_query_timestamps[query_type] = [time.monotonic()]
        else:
            self._graphql_query_timestamps[query_type].append(time.monotonic())

    def handle_429(self, query_type: str) -> None:
        """This method is called to handle a 429 Too Many Requests response. It calls :meth:`RateController.sleep` to
         wait until we can repeat the same request."""
        current_time = time.monotonic()
        waittime = self.query_waittime(query_type, current_time, True)
        assert waittime >= 0
        self._dump_query_timestamps(current_time, query_type)
        text_for_429 = ("Instagram responded with HTTP error \"429 - Too Many Requests\". Please do not run multiple "
                        "instances of InstaDownloader in parallel or within short sequence. Also, do not use any Instagram "
                        "App while InstaDownloader is running.")
        self._context.error(textwrap.fill(text_for_429), repeat_at_end=False)
        if waittime > 1.5:
            self._context.error("The request will be retried in {} seconds, at {:%H:%M}."
                                .format(round(waittime), datetime.now() + timedelta(seconds=waittime)),
                                repeat_at_end=False)
        if waittime > 0:
            self.sleep(waittime)


def get_default_session_filename(username: str) -> str:
    """Returns default session filename for given username."""
    sessionfilename = "session-{}".format(username)
    if platform.system() == "Windows":
        # on Windows, use %LOCALAPPDATA%\InstaDownloader\session-USERNAME
        localappdata = os.getenv("LOCALAPPDATA")
        if localappdata is not None:
            return os.path.join(localappdata, "InstaDownloader", sessionfilename)
        # legacy fallback - store in temp dir if %LOCALAPPDATA% is not set
        return os.path.join(tempfile.gettempdir(), ".instadownloader-" + getpass.getuser(), sessionfilename)
    # on Unix, use ~/.config/instadownloader/session-USERNAME
    return os.path.join(os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "instadownloader",
                        sessionfilename)


def get_legacy_session_filename(username: str) -> str:
    """Returns legacy (until v4.4.3) default session filename for given username."""
    dirname = tempfile.gettempdir() + "/" + ".instadownloader-" + getpass.getuser()
    filename = dirname + "/" + "session-" + username
    return filename.lower()


if __name__ == '__main__':
    open('log.txt', "w+")
    print('    ____           __        ____                      __                __          ')
    print('   /  _/___  _____/ /_____ _/ __ \____ _      ______  / /___  ____ _____/ /__  _____ ')
    print('   / // __ \/ ___/ __/ __ `/ / / / __ \ | /| / / __ \/ / __ \/ __ `/ __  / _ \/ ___/ ')
    print(' _/ // / / (__  ) /_/ /_/ / /_/ / /_/ / |/ |/ / / / / / /_/ / /_/ / /_/ /  __/ /     ')
    print('/___/_/ /_/____/\__/\__,_/_____/\____/|__/|__/_/ /_/_/\____/\__,_/\__,_/\___/_/      ')
    print('')
    with open('config.json') as config_json:
        config = json.load(config_json)
    with open('creds.json') as creds_json:
        creds = json.load(creds_json)
    username = creds["username"]
    password = creds["password"]
    worker = InstaDownloader()
    worker.setup_session(username)
    worker.log("Logged in as %s." % username)
    try:
        worker.main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        # Save session if it is useful
        exit_handler()
