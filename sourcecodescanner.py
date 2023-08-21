#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""Простой антивирус 'Delta' на Python
Разработчик: Okulus Dev (C) 2023
Лицензия: GNU GPL v3"""
from functools import cache
from colorama import Fore, Style


@cache
def check_py_script(filename: str):
	print(f'[+] Ищем угрозы в {filename}...')

	detects = {
		'scapy': {
			'info': 'Найдена угроза административной работы с сетью при помощи scapy',
			'detects': ['from scapy import *', 'from scapy.all import *',
					'from scapy.all import sniff', 'import scapy'],
		},
		'pynput': {
			'info': 'Найдена угроза кейлоггера или работы с клавиатурой через pynput',
			'detects': ['import pynput', 'from pynput.keyboard import Key, Listener',
					'from pynput.keyboard import Listener, Key', 'from pynput.keyboard import Key',
					'from pynput.keyboard import Listener']
		},
		'socket': {
			'info': 'Найдена угроза работы с сервером и интернетом через сеть при помощи socket',
			'detects': ['import socket', 'from socket import *']
		},
		'smtplib': {
			'info': 'Найдена угроза отправки информации на почту или взаимодействия с smtp через smtplib',
			'detects': ['import smtplib as smtp', 'import smtplib', 'from smtplib import *']
		},
		'psutil/platform': {
			'info': 'Найдена угроза получения информации о ПК, сети и оборудования через psutil/platform',
			'detects': ['import platform', 'from platform import uname', 'from platform import *',
						'from psutil import *', 'import psutil']
		},
		'pyAesCrypt': {
			'info': 'Найдена угроза шифрования файлов через pyAesCrypt',
			'detects': ['from pyAesCrypt import *', 'import pyAesCrypt']
		},
		'subprocess': {
			'info': 'Найдена уязвимость работы с терминалом или командной строкой через subprocess',
			'detects': ['from subprocess import *', 'import subprocess']
		},
		'ctypes': {
			'info': 'Найдена уязвимость для работы с внешними библиотеками при помощи ctypes',
			'detects': ['import ctypes', 'from ctypes import *']
		},
		'win32': {
			'info': 'Найдена уязвимость для работы с Win32 API',
			'detects': ['import pywin32', 'import win32', 'from pywin32 import *', 'from win32 import *']
		}
	}

	dangers = []

	try:
		with open(filename, 'r') as file:
			pycode = file.read().split('\n')

		line_num = 0
		for line in pycode:
			line_num += 1
			print(f'Сканирование {line_num} строки кода...')
			if line.startswith('#') or line.startswith("'''") or line.startswith('"""'):
				continue
			for detect_type in detects:
				for detect in detects[detect_type]['detects']:
					if detect == line:
						print(f'{Fore.RED}[! {detect_type}] Номер строки: {line_num}: {detects[detect_type]["info"]}{Style.RESET_ALL}')
						dangers.append(f'{Fore.RED}[! {detect_type}] {line_num}: {detects[detect_type]["info"]}{Style.RESET_ALL}')
						continue

		print(f'[+] Сканирование {filename} закончено')

		if len(dangers) > 0:
			print(f'[+] Обнаружено угроз в {filename}:')
			for danger in dangers:
				print(danger)
		else:
			print(f'[+] Угроз в {filename} нету!')

	except PermissionError:
		print(f'{Fore.RED}[!] Ошибка прав доступа к файлу{Style.RESET_ALL}')
	except FileNotFoundError:
		print(f'{Fore.RED}[!] Файл не найден{Style.RESET_ALL}')
