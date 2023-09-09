#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""Простой антивирус 'Delta' на Python
Разработчик: Okulus Dev (C) 2023
Лицензия: GNU GPL v3"""
import argparse
from functools import cache
from config import *
from signatures_acts import *
from sourcecodescanner import check_py_script
from network import ARPSpoofingDetector
from filescanner import scan_file
from mpscanner import MeterpreterScanner
from colorama import Fore, Style


def main():
	arpspoof_detector = ARPSpoofingDetector()
	print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
╺┳┓┏━╸╻  ╺┳╸┏━┓   ┏━┓┏┓╻╺┳╸╻╻ ╻╻┏━┓╻ ╻┏━┓
 ┃┃┣╸ ┃   ┃ ┣━┫ ━ ┣━┫┃┗┫ ┃ ┃┃┏┛┃┣┳┛┃ ┃┗━┓
╺┻┛┗━╸┗━╸ ╹ ╹ ╹   ╹ ╹╹ ╹ ╹ ╹┗┛ ╹╹┗╸┗━┛┗━┛
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	""")
	description = f'Простой и быстрый антивирус. Если у вас есть вопрос, перейдите на этой ссылке: {report_url}'
	parser = argparse.ArgumentParser(description=description)

	parser.add_argument('--scanfile', help='Сканирование файла на угрозы', required=False)
	parser.add_argument('--deletefile', required=False, choices=['y', 'n'], help='Удалять ли опасный файл при сканировании', default='n')

	parser.add_argument('--detect-arpspoof', required=False, choices=['start'], help='Обнаружение ARP-спуфинга', default='start')

	parser.add_argument('--scan-pyscript', required=False, help='Сканирование python-скриптов на угрозы')

	parser.add_argument('--detect-meterpeter', required=False, help='Сканирование Windows 7/10 на сессии meterpreter', choices=['start'], default='start')

	args = parser.parse_args()

	if args.scanfile:
		if args.deletefile == 'y':
			delete = True
		else:
			delete = False

		scan_file(args.scanfile, False)

		if delete:
			os.remove(args.scanfile)
	if args.detect_arpspoof:
		try:
			arpspoof_detector.sniffing()
		except PermissionError:
			print('[!] Недостаточно прав для запуска детектора ARP-спуфинга. Запустите Delta-Antivirus от имени администратора')
	if args.detect_arpspoof:
		try:
			MeterpreterScanner().finding_meterpreter_sessions()
		except Exception as e:
			print(f'[!] Ошибка: {e}')
	if args.scan_pyscript:
		check_py_script(args.scan_pyscript)


if __name__ == '__main__':
	main()
