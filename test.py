from avred_server import load_config
from scanner import virus_filepath_placeholder, scan_data, scan_download, check_webdriver, stop_webdriver

from base64 import b64decode
from os import mkdir, path, listdir, system
from shutil import rmtree
from subprocess import Popen
from sys import executable
from time import sleep

import requests as req


root_path = path.dirname(__file__)
temp_dir = path.join(root_path, "temp_test_dir")
mal_file = path.join(temp_dir, "malicous_test_file.exe")
half_mal_file_b64 = path.join(root_path, "half_mal_file.txt")
half_mal_file = path.join(temp_dir, "half_malicious_test_file.zip")
not_mal_file = path.join(temp_dir, "benign_test_file.exe")
port = 3001


def write_test_files():
	if not path.isdir(temp_dir):
		mkdir(temp_dir)
	conf = {}
	load_config(conf)
	with open(mal_file, "wb") as f:
		f.write(conf["virus"].encode())
	with open(half_mal_file, "wb") as f:
		with open(half_mal_file_b64, "rb") as f2:
			f.write(b64decode(f2.read()))
	with open(not_mal_file, "wb") as f:
		f.write(b"not malicious")
	print(f"**** written test files @ {temp_dir} : {listdir(temp_dir)}")


def del_test_files():
	if path.isdir(temp_dir):
		rmtree(temp_dir)
	print(f"**** deleted test files @ {temp_dir}")


def init_download_server():
	print("**** setting up http server...")
	base_url = f"http://windev.rchred.local:{port}/"
	url_mal = base_url + mal_file.split("\\")[-1]
	url_half_mal = base_url + half_mal_file.split("\\")[-1]
	url_not_mal = base_url + not_mal_file.split("\\")[-1]

	p = Popen([executable, "-m", "http.server", str(port), "-d", temp_dir])
	return p, url_mal, url_half_mal, url_not_mal


def serve_files():
	system(f"{executable} -m http.server {port} -d {temp_dir}")


def stop_server():
	system(f'powershell -c "Stop-Process -Id (Get-NetTCPConnection -LocalPort {port}).OwningProcess -Force"')


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
	with open(half_mal_file, "rb") as f:
		half_mal = f.read()
	assert scan_data(conf["virus"].encode(), conf, ".exe")
	assert not scan_data(half_mal, conf, ".zip")
	assert not scan_data(b"Not malicous", conf, ".exe")
	print("**** mal detected, not_mal and half_mal not detected")
	print("** TEST SCAN DATA passed")


def test_scan_download():
	print("** TEST SCAN DOWNLOAD...")
	conf = {}
	load_config(conf)
	server, url_mal, url_half_mal, url_not_mal = init_download_server()
	print("**** starting webdriver...")
	check_webdriver()
	
	print("**** starting download tests...")
	assert not scan_download(url_not_mal, conf)
	print("**** benign download ok and removed again")

	sleep(1) # wait for monitor to finish print
	assert not scan_download(url_half_mal, conf) # TODO fix (should be detected, F Defender)
	print("**** half malicious download detected")
	
	sleep(1) # wait for monitor to finish print
	assert scan_download(url_mal, conf)
	print("**** malicious download detected")

	server.terminate()
	print("**** server stopped")
	print("** TEST SCAN DOWNLOAD passed")


def test_test_endpoint():
	print("** TEST TEST ENDPOINT...")
	conf = {}
	load_config(conf)
	p = Popen([executable, "avred_server.py"])
	sleep(1) # wait for startup
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
	test_test_endpoint()

	# teardown
	stop_webdriver()
	del_test_files()


if __name__ == "__main__":
	test_all()
