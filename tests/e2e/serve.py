import sys, time, paramiko; sys.path.insert(0, __import__("os").path.dirname(__file__))
import fake_device
key = paramiko.RSAKey.from_private_key_file(sys.argv[1]); port = int(sys.argv[2])
fake_device.start(key, port)
while True: time.sleep(1)
