from avred_server import load_config
from scanner import virus_filepath_placeholder, scan_data, scan_download, scan_cmd, get_download_path_from_url

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from os import mkdir, path, listdir, remove
from shutil import rmtree
from subprocess import Popen
from sys import executable
from threading import Thread
from time import sleep

import requests as req


root_path = path.dirname(__file__)
temp_dir = path.join(root_path, "temp_test_dir")
mal_file = path.join(temp_dir, "malicous_test_file.exe")
not_mal_file = path.join(temp_dir, "benign_test_file.exe")
httpd = None


def write_test_files():
	if not path.isdir(temp_dir):
		mkdir(temp_dir)
	conf = {}
	load_config(conf)
	with open(mal_file, "wb") as f:
		f.write(conf["virus"].encode())
	with open(not_mal_file, "wb") as f:
		f.write(b"not malicious")
	print(f"**** written test files @ {temp_dir} : {listdir(temp_dir)}")


def del_test_files():
	if path.isdir(temp_dir):
		rmtree(temp_dir)
	print(f"**** deleted test files @ {temp_dir}")


def rm_if_exists(filepath):
	if path.isfile(filepath):
		print("**** deleting", filepath)
		remove(filepath)


def init_download_server():
	print("**** setting up http server...")
	port = 3001
	base_url = f"http://localhost:{port}/"
	url_mal = base_url + mal_file.split("\\")[-1]
	url_not_mal = base_url + not_mal_file.split("\\")[-1]

	t = Thread(target=serve_files, args=(port, temp_dir))
	t.start()
	return url_mal, url_not_mal, t


def serve_files(port, temp_dir):
	global httpd
	class Handler(SimpleHTTPRequestHandler):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, directory=temp_dir, **kwargs)

	httpd = TCPServer(("", port), Handler)
	print(f"**** starting server at localhost:{port} inside {temp_dir}")
	httpd.serve_forever()


def test_load_config():
	print("** TEST LOAD CONFIG...")
	conf = {}
	load_config(conf)
	# assert that conf["cmd"] was not overwritten
	assert virus_filepath_placeholder in conf["cmd"]
	assert not any(conf["virus_dir"] in s for s in conf["cmd"])
	print("** TEST LOAD CONFIG passed")


def test_scan_data():
	print("** TEST SCAN DATA...")
	conf = {}
	load_config(conf)
	assert scan_data(conf["virus"].encode(), conf)
	assert not scan_data(b"Not malicous", conf)
	print("** TEST SCAN DATA passed")


def test_scan_download():
	print("** TEST SCAN DOWNLOAD...")
	conf = {}
	load_config(conf)
	url_mal, url_not_mal, t = init_download_server()
	sleep(10) # wait for server startup, TODO: improve, check every sec for server up
	print("**** starting download tests...")
	try:
		download_path = get_download_path_from_url(url_not_mal, conf)
		rm_if_exists(download_path)
		assert not scan_download(url_not_mal, conf)
		rm_if_exists(download_path)
		print("**** benign download ok and removed again")
		sleep(1)
		assert scan_download(url_mal, conf)
		print("**** malicious download detected")
		print("** TEST SCAN DOWNLOAD passed")
	except BaseException as e:
		print("** TEST SCAN DOWNLOAD failed. Err:", e)
	finally:
		httpd.shutdown()
		t.join()
		print("**** stopped server")


def test_scan_cmd():
	print("** TEST SCAN CMD...")
	conf = {}
	load_config(conf)
	assert scan_cmd(mal_file, conf)
	assert not scan_cmd(not_mal_file, conf)
	print("** TEST SCAN CMD passed")


def test_test_endpoint():
	print("** TEST TEST ENDPOINT...")
	conf = {}
	load_config(conf)
	p = Popen([executable, "avred_server.py"])
	status = req.get(f"http://localhost:{conf['port']}/test").status_code
	assert status == 200
	p.terminate()
	print("** TEST TEST ENDPOINT passed")


def test_all():
	# setup
	write_test_files()

	test_load_config()
	test_scan_data()
	test_scan_download()
	test_scan_cmd()
	test_test_endpoint()

	# teardown
	del_test_files()


if __name__ == "__main__":
	test_all()
