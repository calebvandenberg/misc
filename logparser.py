import os
import apache_log_parser as alp
from pprint import pprint

"""Create a list of dictionaries from lines in an apache log file"""

log_path = "c:\\Users\\Caleb\\Desktop\\"
log_file = 'other_vhosts_access.log'
filename = os.path.join(log_path,log_file)

def join_log_files(*args):
    """concatenate log files"""
    if len(args) < 2:
        print("need at least 2 logs to join")
        return None
    logs = []
    for log in args:
        with open(log) as f:
            logs += f.readlines()
    return logs

# using pattern of filename and filename.1, typical cron backup
logs = join_log_files(filename + '.1', filename)

def line_test(line, length=1):
    """makes debugging parse_string regex easier"""
    line = line.split()
    print ' '.join(line[:length])

line_test(logs[1], 5)

parse_string = '%v:%p %a - - %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\"'
log_parser = alp.make_parser(parse_string)
parsed_log = [log_parser(l) for l in logs]

pprint(parsed_log[0])

"""                          Stuff 2 Parse
    '%a'  # Remote IP-address
    '%A'  # Local IP-address
    '%B'  # Size of response in bytes, excluding HTTP headers.
    '%b'  # Size of response in bytes, excluding HTTP headers. In CLF format, i.e. a '-' rather than a 0 when no bytes are sent.
    '%D'  # The time taken to serve the request, in microseconds.
    '%f'  # Filename
    '%h'  # Remote host
    '%H'  # The request protocol
    '%k'  # Number of keepalive requests handled on this connection. Interesting if KeepAlive is being used, so that, for example, a '1' means the first keepalive request after the initial one, '2' the second, etc...; otherwise this is always 0 (indicating the initial request). Available in versions 2.2.11 and later.
    '%l'  # Remote logname (from identd, if supplied). This will return a dash unless mod_ident is present and IdentityCheck is set On.
    '%m'  # The request method
    '%p'  # The canonical port of the server serving the request
    '%P'  # The process ID of the child that serviced the request.
    '%q'  # The query string (prepended with a ? if a query string exists, otherwise an empty string)
    '%r'  # First line of request
    '%R'  # The handler generating the response (if any).
    '%s'  # Status. For requests that got internally redirected, this is the status of the *original* request --- %>s for the last.
    '%t'  # Time the request was received (standard english format)
    '%T'  # The time taken to serve the request, in seconds.
    '%u'  # Remote user (from auth; may be bogus if return status (%s) is 401)
    '%U'  # The URL path requested, not including any query string.
    '%v'  # The canonical ServerName of the server serving the request.
    '%V'  # The server name according to the UseCanonicalName setting.
    '%X'  # Connection status when response is completed:
              # X = connection aborted before the response completed.
              # + = connection may be kept alive after the response is sent.
              # - = connection will be closed after the response is sent.
              # (This directive was %c in late versions of Apache 1.3, but this conflicted with the historical ssl %{var}c syntax.)
    '%I'  # Bytes received, including request and headers, cannot be zero. You need to enable mod_logio to use this.
    '%O'  # Bytes sent, including headers, cannot be zero. You need to enable mod_logio to use this.

    '%\{User-Agent\}i'  # Special case of below, for matching just user agent
    '%\{[^\}]+?\}i'  #  The contents of Foobar: header line(s) in the request sent to the server. Changes made by other modules (e.g. mod_headers) affect this. If you're interested in what the request header was prior to when most modules would have modified it, use mod_setenvif to copy the header into an internal environment variable and log that value with the %\{VARNAME}e described above.

    '%\{[^\}]+?\}C'  #  The contents of cookie Foobar in the request sent to the server. Only version 0 cookies are fully supported.
    '%\{[^\}]+?\}e'  #  The contents of the environment variable FOOBAR
    '%\{[^\}]+?\}n'  #  The contents of note Foobar from another module.
    '%\{[^\}]+?\}o'  #  The contents of Foobar: header line(s) in the reply.
    '%\{[^\}]+?\}p'  #  The canonical port of the server serving the request or the server's actual port or the client's actual port. Valid formats are canonical, local, or remote.
    '%\{[^\}]+?\}P'  #  The process ID or thread id of the child that serviced the request. Valid formats are pid, tid, and hextid. hextid requires APR 1.2.0 or higher.
    '%\{[^\}]+?\}t'  #  The time, in the form given by format, which should be in strftime(3) format. (potentially localized)
    '%\{[^\}]+?\}x'  # Extension value, e.g. mod_ssl protocol and cipher"""
