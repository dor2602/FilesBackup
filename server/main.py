import utils
import server

if __name__ == '__main__':
    PORT_INFO = "port.info"
    port = utils.parsePort(PORT_INFO)
    if port is None:
        svr = server.Server('', '1234')
    else:
        svr = server.Server('', port)  # don't care about host
    if not svr.start():
        print("cant start server")
