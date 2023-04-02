def stopServer(err):
    """ print err and stop script execution """
    print(f"\nFatal Error: {err}\nBackup Server will halt!")
    exit(1)


def parsePort(filepath):
    """ parse port """
    port = None
    try:
        with open(filepath, "r") as port_info:
            port = port_info.readline().strip()
            port = int(port)
    except (ValueError, FileNotFoundError):
        port = None
    finally:
        return port
