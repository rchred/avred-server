import logging
from monitor import monitor_dir
from os.path import isfile, join
from os import path, remove
from subprocess import PIPE, DEVNULL, run, TimeoutExpired
from random import choice
from string import ascii_letters
from threading import Thread
from time import sleep


virus_filepath_placeholder = "VIRUS_FILEPATH_PLACEHOLDER"
stop_signal_filename = "STOP_DOWNLOAD_SCAN.txt"


def save_file(data, filepath):
	try:
		logging.info(f"Writing data to file: {filepath}")
		with open(filepath, "wb") as f:
			f.write(data)
		return True
	except BaseException as e:
		logging.info(f"Could not save virus file! Exception: {str(e)}")
		return False


def delete_file(filepath):
	try:
		remove(filepath)
	except BaseException:
		logging.info("Could not delete virus file, it's probably held by some process.")


def get_random_filename(ext):
	if not ext:
		ext = ".exe"
	name = "avred-test"
	rand = "".join([choice(ascii_letters) for _ in range(6)])
	new_name = f"{name}-{rand}{ext}"
	return new_name


def scan_data(contents, conf, ext):
	filepath = join(conf["virus_dir"], get_random_filename(ext))
	if not save_file(contents, filepath):
		err = "Virus file could not be saved!"
		logging.info(err)
		raise Exception(err)
	return scan_cmd(filepath, conf)


def expand_ps_envvars(s):
	# $env:localappdata -> no expansion; $localappdata -> gets expanded
	s = s.replace("$env:", "$")
	s = path.expandvars(s)
	return s.replace("'", "") # expanded string has '' around


def rm_if_exists(ps_filepath):
	filepath = expand_ps_envvars(ps_filepath)
	if path.isfile(filepath):
		try:
			remove(filepath)
		except PermissionError:
			print(f"[#] Waiting for Windows to release {filepath}")
			sleep(0.5)


def get_download_path_from_url(url, conf):
	download_name = url.split("/")[-1]
	download_path = conf["download_path"].replace("{{download_name}}", download_name)
	download_path = expand_ps_envvars(download_path)
	return download_path


def scan_download(download_url, conf):
	download_path = get_download_path_from_url(download_url, conf)
	download_folder, download_name = download_path.rsplit("\\", 1)
	stop_signal_filepath = path.join(download_folder, stop_signal_filename)
	chrome_path = conf["downloader"]
	chrome_args = conf["download_args"].replace("{{download_url}}", download_url)

	cmd = f"powershell -c \"\
		$p = Start-Process -FilePath {chrome_path} -ArgumentList {chrome_args} -PassThru; $i=3; \
		While ($i -lt {conf['download_timeout']}) \
			{{sleep -m 100; $i+=0.1; If ((Test-Path {download_path}) -or (Test-Path {stop_signal_filepath})) \
				{{break}}\
			}}; \
		Stop-Process $p.id -Force\""
	
	rm_if_exists(stop_signal_filepath)
	t = Thread(target=monitor_dir, args=(download_folder, download_name, stop_signal_filepath))
	t.start()

	try:
		stdout = run(
			cmd,
			check=False,
			stdin=DEVNULL, # do not wait for user input
			stdout=PIPE,
			timeout=conf["download_timeout"]
		).stdout
		logging.info("Download Result: " + str(stdout))
	except TimeoutExpired: # refactor timeout, replace with monitor_dir
		logging.info("File not downloaded, already detected as virus.")
		return True
	rm_if_exists(stop_signal_filepath)
	
	if not isfile(download_path):
		return True # also detected as virus
	
	return scan_cmd(download_path, conf) # TODO, check if works


def scan_cmd(filepath, conf):
	logging.info(f"Scanning file: {filepath}")
	try:
		cmd = list(map(lambda x: x.replace(virus_filepath_placeholder, filepath), conf["cmd"]))
		stdout = run(
			cmd,
			check=False,
			stdin=DEVNULL, # do not wait for user input
			stdout=PIPE,
			timeout=conf["av_timeout"]
		).stdout
	except TimeoutExpired:
		err = "Did not finish scan within timeout window!"
		logging.info(err)
		raise Exception(err)

	logging.info("Scan Result: " + str(stdout))

	# AV detected and removed the file, add AV exception for path
	if not isfile(filepath):
		err = f"File was removed before or at scan time! Add {conf['virus_dir']} to AV whitelist."
		logging.info(err)
		raise Exception(err)

	delete_file(filepath)
	if conf["virus_detected"].encode() in stdout:
		logging.info("Virus detected with Scan")
		return True
	else:
		logging.info("No Virus detected with Scan")
		return False
