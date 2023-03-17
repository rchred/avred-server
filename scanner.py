import requests as req
from monitor import get_latest_event, get_start_as_utc_datetime
from os.path import isfile, join
from os import path, remove
from subprocess import PIPE, DEVNULL, run, TimeoutExpired, CalledProcessError
from random import choice
from string import ascii_letters
from threading import Thread
from time import sleep, time

import logging

logging.basicConfig(
	filename="log.txt",
	format="%(asctime)s - %(levelname)s - %(message)s",
	level=logging.INFO
)

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
			sleep(0.1)


def check_download_url(url):
	try:
		res = req.get(url)
		return res.status_code == 200 and len(res.text)
	except req.exceptions.ConnectionError:
		return False


def get_download_path_from_url(url, conf):
	download_name = url.split("/")[-1]
	download_path = conf["download_path"].replace("{{download_name}}", download_name)
	download_path = expand_ps_envvars(download_path)
	return download_path


def download_file(download_cmd, conf):
	try:
		stdout = run(
			download_cmd,
			stdin=DEVNULL, # do not wait for / accept user input
			stdout=PIPE,
			timeout=conf["download_timeout"]
		).stdout
		logging.info("Download Result: " + str(stdout))
	except TimeoutExpired:
		pass # already handled in scan_download()


def scan_download(download_url, conf):
	if not check_download_url(download_url):
		err = "Download URL not reachable, or status != 200, or empty response."
		logging.info(err)
		raise Exception(err)
	
	# TODO implement selenium (then implement stop signal better)
	stop_signal_filepath = path.join(conf["virus_dir"], stop_signal_filename)

	download_path = get_download_path_from_url(download_url, conf)
	download_folder, _ = download_path.rsplit("\\", 1)
	
	chrome_path = conf["downloader"]
	chrome_args = conf["download_args"].replace("{{download_url}}", download_url)

	cmd = f"powershell -c \"\
		$p = Start-Process -FilePath {chrome_path} -ArgumentList {chrome_args} -PassThru; $i=3; \
		While ($i -lt {conf['download_timeout']}) \
			{{sleep -m 100; $i+=0.1; If ((Test-Path {download_path}) -or (Test-Path {stop_signal_filepath})) \
				{{break}}\
			}}; \
		Stop-Process $p.id -Force\""
	
	# try to download the file
	print("downloading to:", download_path)
	rm_if_exists(stop_signal_filepath)
	t = Thread(target=download_file, args=(cmd, conf))
	start_utc = get_start_as_utc_datetime()
	start = time()
	t.start()
	while not path.isfile(download_path):
		event = get_latest_event()
		print(event)
		sleep(1)
		if event.time > start_utc:
			# got new defender event, check if this is from our download just now
			if download_folder in event.path and "chrome.exe" in event.proc:
				return True
			# else: unrelated event, just continue
		if time() > start+conf["download_timeout"]:
			err = "File not downloaded, and also not detected as virus."
			logging.info(err)
			raise Exception(err)
		
	# file is now downloaded, send exit signal to the downloader
	with open(stop_signal_filepath, "w") as f:
		f.write("stop")
	t.join() # wait for the downloader to read the exit signal, then continue here
	rm_if_exists(stop_signal_filepath)

	# the file is now downloaded to download_path, and not yet detected as a virus
	# now interact with the file, to check if Defender detects it now
	try:
		run(f"type {download_path}", check=True, shell=True, stdout=DEVNULL)
	except CalledProcessError:
		# Operation did not complete successfully because the file contains a virus or potentially unwanted software.
		# subprocess.CalledProcessError: Command 'type C:\Users\hacker\Downloads\Audio.zip' returned non-zero exit status 1.
		# -> detected as Virus
		logging.info(f"Downloaded, but detected as virus: {get_latest_event()}")
		return False
	
	# file downloaded and successfully interacted, now scan the raw data, TODO: is this even useful now?
	return scan_cmd(download_path, conf)


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
		err = "Did not finish scan within timeout window."
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
