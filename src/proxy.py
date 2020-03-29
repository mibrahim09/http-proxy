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

        print("*" * 50)
        print("[to_http_string] Implement me!")
        print("*" * 50)
        return None

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
        """ Same as above """
        pass

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
    def start_validation(self):
        arr = self.data.replace('\r\n\r\n', '').split(self.newline)
        Expect_host = arr[0].split(' ')[1].startswith('\\')
        HttpVersion = ''
        host = ''
        Sublink = ''
        reply = ''
        request_type = ''
        valid = True
        host = ''
        port = 80
        # if Expect_host: # validate host part.
        #     if len(arr) != 1:
        #         host = arr[1].split(':')[1]
        #         valid = True
        #     pass
        # else:
        #     valid = True
        ############# validate the first string.
        if valid:
            items = arr[0].split(' ');
            if items[0] == 'GET':
                request_type = items[0]
                valid = True  # First part.
                if len(items) != 3:
                    valid = False
                    reply = self.BadRequest
                else:
                    if Expect_host:
                        Sublink = items[1]
                    else:
                        host = items[1]
                    HttpVersion = items[2]
                    valid = True
                    pass
                pass
            else:
                valid = False
                reply = self.NotImplemented
            pass

        # GET HOST
        if Expect_host:  # validate host part.
            if len(arr) != 1:
                for i in range(1, len(arr)):
                    splited = arr[i].split(':')
                    if len(splited) != 2:  # must be 2 at least
                        valid = False
                        reply = self.BadRequest
                    elif splited[0] == 'Host':
                        host = splited[1]
                        valid = True
                pass
            else:
                valid = True
        #####################
        # Check for port.
        splited2 = host.split(':')
        if len(splited2) == 2:
            port = int(splited2[1])
            host = splited2[0] + Sublink

        if not valid:
            print(reply)
        else:
            print('Request Type:', request_type)
            print('Version:', HttpVersion)
            print('Host:', host)
            print('Port:', port)

        # Send Request to Server.
        if valid:
            sock_address = (host, port)
            request_packet = struct.pack(str(len(self.data))
                                         + 's', bytes(self.data, 'utf-8'))

            httpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            httpSocket.connect(sock_address)
            httpSocket.sendto(request_packet, sock_address)

            (received_packet, (sock_address)) = httpSocket.recvfrom(20000)
            self.send(received_packet)
            print('Reply sent back to client.')

        else:
            packed = struct.pack(str(len(reply)) + 's', bytes(reply, 'utf-8'))
            self.send(packed)
        self.close()
        pass

    def handle_read(self):
        data_buff = self.recv(4096 * 4)
        current = data_buff.decode("utf-8")
        self.data += current
        if self.data.endswith('\r\n\r\n'):
            print('Send response now.')
            self.start_validation()
        else:
            os.system('cls')
        print(self.data)

    # def handle_write(self):
    # print('im here')
    # sent = self.send(struct.pack(str(len(self.data))
    #                             + 's', bytes(self.data, 'utf-8')))
    # self.data = self.data[sent:]
    # print('done')


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """

    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.
    print("*" * 50)
    print("[setup_sockets] Implement me!")
    print("*" * 50)
    return None


def do_socket_logic():
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.

    Feel free to delete this function.
    """
    pass


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Parses the given HTTP request
    - Validates it
    - Returns a sanitized HttpRequestInfo or HttpErrorResponse
        based on request validity.

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    parsed = parse_http_request(source_addr, http_raw_data)

    # Validate, sanitize, return Http object.
    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)
    return None


def parse_http_request(source_addr, http_raw_data) -> HttpRequestInfo:
    """
    This function parses an HTTP request into an HttpRequestInfo
    object.

    it does NOT validate the HTTP request.
    """
    print("*" * 50)
    print("[parse_http_request] Implement me!")
    print("*" * 50)
    # Replace this line with the correct values.
    ret = HttpRequestInfo(None, None, None, None, None, None)
    return ret


def check_http_request_validity(http_request_info: HttpRequestInfo) -> HttpRequestState:
    """
    Checks if an HTTP response is valid

    returns:
    One of values in HttpRequestState
    """
    print("*" * 50)
    print("[check_http_request_validity] Implement me!")
    print("*" * 50)
    # return HttpRequestState.GOOD (for example)
    return HttpRequestState.PLACEHOLDER


def sanitize_http_request(request_info: HttpRequestInfo) -> HttpRequestInfo:
    """
    Puts an HTTP request on the sanitized (standard form)

    returns:
    A modified object of the HttpRequestInfo with
    sanitized fields

    for example, expand a URL to relative path + Host header.
    """
    print("*" * 50)
    print("[sanitize_http_request] Implement me!")
    print("*" * 50)
    ret = HttpRequestInfo(None, None, None, None, None, None)
    return ret


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
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)
    """

    Socket = EchoServer(('127.0.0.1', 220))
    asyncore.loop()


if __name__ == "__main__":
    main()
