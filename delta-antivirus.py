#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""Простой антивирус 'Delta' на Python
Разработчик: Okulus Dev (C) 2023
Лицензия: GNU GPL v3"""
import argparse
from functools import cache
from tkinter import filedialog
from signatures_acts import *
from sourcecodescanner import check_py_script
from network import ARPSpoofingDetector
from filescanner import scan_file
from mpscanner import MeterpreterScanner
from config import *
from colorama import Fore, Style
import customtkinter as ctk


def get_pathfile():
	filepath = filedialog.askopenfilename()

	if filepath != "":
		with open(filepath, "r") as file:
			text = file.read()

		print(scan_file(filepath))


class App(ctk.CTk):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.title_font = ctk.CTkFont(family='Roboto', size=20)
		self.button_font = ctk.CTkFont(family='Roboto', size=17)

		self.title("Delta Antivirus")
		self.geometry("600x700")
		self.resizable(False, False)

		self.nameLabel = ctk.CTkLabel(self, text="Delta Antivirus - Легкий, быстрый антивирус", font=self.title_font)
		self.nameLabel.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
		self.openfilebutton = ctk.CTkButton(self, text='Сканирование файла на угрозы', 
											command=get_pathfile, font=self.button_font)
		self.openfilebutton.grid(row=1, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

		self.displayBox = ctk.CTkTextbox(self, width=400, height=200)
		self.displayBox.grid(row=6, column=0, columnspan=4, padx=20, pady=20, sticky="nsew")


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

	parser.add_argument('--launch', help='Запуск', required=True, default='gui', choices=['gui', 'cli'])

	parser.add_argument('--scanfile', help='Сканирование файла на угрозы', required=False)
	parser.add_argument('--deletefile', required=False, choices=['y', 'n'], help='Удалять ли опасный файл при сканировании', default='n')

	parser.add_argument('--detect-arpspoof', required=False, choices=['start'], help='Обнаружение ARP-спуфинга', default='start')

	parser.add_argument('--scan-pyscript', required=False, help='Сканирование python-скриптов на угрозы')

	parser.add_argument('--detect-meterpreter', required=False, help='Сканирование Windows 7/10 на сессии meterpreter', choices=['start'], default='start')

	args = parser.parse_args()

	if args.launch:
		if args.launch == 'gui':
			ctk.set_appearance_mode("Dark")
			ctk.set_default_color_theme("green") 
			
			app = App()
			app.mainloop()
		else:
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
			if args.detect_meterpreter:
				try:
					MeterpreterScanner().finding_meterpreter_sessions()
				except Exception as e:
					print(f'[!] Ошибка: {e}')
			if args.scan_pyscript:
				check_py_script(args.scan_pyscript)


if __name__ == '__main__':
	main()
