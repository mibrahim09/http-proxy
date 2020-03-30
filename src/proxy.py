# Don't forget to change this file's name before submission.
import sys
import os
import enum
import asyncore
import socket
import logging
import struct

clear = lambda: os.system('cls')  # on Windows System


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """
    HTTP_REQUEST_TYPE = 'HTTP/1.0'

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of tuples
        # for example ("Host", "www.google.com")
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ("Host", "www.google.com") note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def getClientInfo(self):
        return (self.requested_host, self.requested_port)

    def SetHTTP(self, HTTP_REQUEST):
        self.HTTP_REQUEST_TYPE = HTTP_REQUEST

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        ToRet = '';

        ToRet += self.method + ' '
        if self.requested_path == '':
            ToRet += self.requested_path
        else:
            ToRet += self.requested_path
        ToRet += ' ' + self.HTTP_REQUEST_TYPE + '\r\n'

        for item in self.headers:
            ToRet += item[0] + ': ' + item[1] + '\r\n'

        ToRet += '\r\n'
        return ToRet

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return str(str(self.code) + ' ' + self.message)

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


class EchoServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each client.
    """

    def __init__(self, address):
        self.logger = logging.getLogger('EchoServer')
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(address)
        self.address = self.socket.getsockname()
        self.logger.debug('binding to %s', self.address)
        self.listen(10)
        print('Listening on the socket.')
        return

    def handle_accept(self):
        # Called when a client connects to our socket
        client_info = self.accept()
        self.logger.debug('handle_accept() -> %s', client_info[1])
        EchoHandler(sock=client_info[0])
        # We only want to deal with one client at a time,
        # so close as soon as we set up the handler.
        # Normally you would not do this and the server
        # would run forever or until it received instructions
        # to stop.
        # self.handle_close()
        return

    def handle_close(self):
        self.logger.debug('handle_close()')
        self.close()
        return


class EchoHandler(asyncore.dispatcher):
    """Handles echoing messages from a single client.
    """
    data = ''
    lastchar1 = ''
    lastchar2 = ''
    newline = '\r\n'
    BadRequest = '401 Bad Request'
    NotImplemented = 'Not Implemented (501)'

    def handle_read(self):
        data_buff = self.recv(4096 * 4)
        current = data_buff.decode("utf-8")
        self.data += current
        if self.data.endswith('\r\n\r\n'):
            Packet, valid = http_request_pipeline(self.addr, self.data)
            if valid:

                sock_address = Packet.getClientInfo()
                request_packet = Packet.to_byte_array(Packet.to_http_string())

                httpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                httpSocket.connect(sock_address)
                httpSocket.sendto(request_packet, sock_address)

                (received_packet, (sock_address)) = httpSocket.recvfrom(20000)
                self.send(received_packet)

            else:
                packed = Packet.to_byte_array(Packet.to_http_string())
                self.send(packed)
            self.close()

        else:
            os.system('cls')
        print(self.data)


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    Socket = EchoServer(('127.0.0.1', proxy_port_number))
    asyncore.loop()
    return None


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.
    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo
    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.
    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)
    if validity == HttpRequestState.GOOD:
        print('GOOD AND READY')
        Request = parse_http_request(source_addr, http_raw_data)
        return Request, True
    else:
        code = 0
        msg = ''
        print('ERROR:', validity)
        if validity == HttpRequestState.NOT_SUPPORTED:
            code = 501
            msg = 'Not Supported'
        else:
            code = 400
            msg = 'Bad Request'
        ErrorPacket = HttpErrorResponse(code, msg)
        ErrorPacket.display()
        return ErrorPacket, False


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """
    print("[parse_http_request] Parsing the HTTP Request")

    # def __init__(self, client_info, method: str, requested_host: str,
    #              requested_port: int,
    #              requested_path: str,
    #              headers: list):

    # Headers will be represented as a list of tuples
    # for example ("Host", "www.google.com")
    # if you get a header as:
    # "Host: www.google.com:80"
    # convert it to ("Host", "www.google.com") note that the
    # port is removed (because it goes into the request_port variable)

    method = ''
    Host = ''
    HTTP_REQUEST_TYPE = ''
    Path = ''
    Requested_Port = 80

    arr = http_raw_data.replace('\r\n\r\n', '').split('\r\n')
    firstReq = arr[0].split(' ')
    method = firstReq[0]
    Host = firstReq[1]
    HTTP_REQUEST_TYPE = firstReq[2]
    HeadersList = []

    # Search for the Host & Fill the Headers.
    if Host.startswith('/'):
        Path = Host
        # Get the Host.
        for i in range(1, len(arr)):
            splited = arr[i].split(':')
            if splited[0] == 'Host':
                Host = splited[1].replace(' ', '')
                HeadersList.append(['Host', Host])
            else:
                HeadersList.append([splited[0], splited[1]])
        pass
    # The Port.
    Splited2 = Host.split(':')
    if len(Splited2) == 2:
        Requested_Port = int(Splited2[1])
        Host = Splited2[0]

    # Replace this line with the correct values.
    ret = HttpRequestInfo(source_addr, method, Host, Requested_Port, Path, HeadersList)
    ret.SetHTTP(HTTP_REQUEST_TYPE)
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid
    returns:
    One of values in HttpRequestState
    """
    arr = http_raw_data.replace('\r\n\r\n', '').split('\r\n')
    HttpVersion = ''
    host = ''
    Sublink = ''
    reply = ''
    request_type = ''
    valid = True
    NotSupported = False
    host = ''
    port = 80
    Expect_host = False

    # validate the first string.
    items = arr[0].split(' ');
    request_type = items[0]
    valid = True  # First part.
    if len(items) != 3:
        valid = False
        return HttpRequestState.INVALID_INPUT
    else:
        if items[1].startswith('/'):
            Sublink = items[1]
            Expect_host = True
        else:
            host = items[1]
            HttpVersion = items[2]
            valid = True
        pass
    pass
    if items[0] == 'HEAD' or items[0] == 'POST' or items[0] == 'PUT':
        NotSupported = True
    elif items[0] == 'GET':
        valid = True
    else:
        valid = False
    pass
    if items[2] == '':
        valid = False

    # GET HOST
    if valid:  # validate host part.
        if Expect_host and len(arr) < 2:
            valid = False
        if valid and len(arr) != 1:
            for i in range(1, len(arr)):
                if arr[i] == '':
                    break
                splited = arr[i].split(':')
                if len(splited) != 2:  # must be 2 at least
                    valid = False
                    break
                elif splited[0] == 'Host':
                    host = splited[1]
                    valid = True
            pass
        else:
            valid = False
        #####################
        # Check for port.
        ToSplit = host.replace('https://', '')
        ToSplit = host.replace('http://', '')
        splited2 = ToSplit.split(':')
        if len(splited2) == 2:
            port = int(splited2[1])
            host = splited2[0]

    if not valid:
        print(reply)
    else:
        print('Request Type:', request_type)
        print('Version:', HttpVersion)
        print('Host:', host)
        print('Port:', port)

    if not valid:
        return HttpRequestState.INVALID_INPUT

    if NotSupported:
        return HttpRequestState.NOT_SUPPORTED
    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.
    for example, expand a full URL to relative path + Host header.
    returns:
    nothing, but modifies the input object
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
