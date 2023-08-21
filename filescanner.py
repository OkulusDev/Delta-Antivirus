#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""Простой антивирус 'Delta' на Python
Разработчик: Okulus Dev (C) 2023
Лицензия: GNU GPL v3"""
import os
from functools import cache
from time import perf_counter
from hashlib import sha256, sha1, md5
from config import *
from colorama import Fore, Style
import vt


@cache
def scan_file(filename: str, delete_file: bool=False) -> None:
	print(f'Сканируем {filename} на наличие угроз...')
	try:
		start = perf_counter()
		shahash = sha256()
		sha1hash = sha1()
		md5hash = md5()

		with open(filename, 'rb') as file:
			while True:
				data = file.read()
				if not data:
					break
				shahash.update(data)
				sha1hash.update(data)
				md5hash.update(data)

			result = shahash.hexdigest()
			result2 = sha1hash.hexdigest()
			result3 = md5hash.hexdigest()
			print(f'{Fore.YELLOW}[+] Проверяем наличие хеша {result} в сигнатурах...{Style.RESET_ALL}')

		with open(signature_resources[0], 'r') as r:
			signatures = list(r.read().split('\n'))

		with open(signature_resources[1], 'r') as r:
			for sign_hash2 in list(r.read().replace(';', '').split('\n')):
				signatures.append(sign_hash2)

		with open(signature_resources[2], 'r') as r:
			for sign_hash3 in list(r.read().replace(';', '').split('\n')):
				signatures.append(sign_hash3)

		with open(signature_resources[3], 'r') as r:
			for sign_hash4 in list(r.read().replace(';', '').split('\n')):
				signatures.append(sign_hash4)

		print(f'''Сканирование {filename} на Virus Total...

Частота запросов     4 поисков / минута
Дневная квота        500 поисков / день
Месячная квота	     15.5 K поисков / месяц''')

		client = vt.Client("API_KEY_VT")

		try:
			print('Попытка нахождения файла...')
			file = client.get_object(f"/files/{result}")
			stats = file.last_analysis_stats

			print(f'''VirusTotal: {filename}
Безвредный: {stats["harmless"]}
Неподдерживаемый тип: {stats["type-unsupported"]}
Подозрительный: {stats["suspicious"]}
Отказ: {stats["failure"]}
Злонамеренный: {stats["malicious"]}
Безопасный: {stats["undetected"]}
		''')
		except vt.error.APIError:
			print('Загрузка файла...')
			with open(filename, "rb") as f:
				analysis = client.scan_file(f, wait_for_completion=True)

			file = client.get_object(f"/files/{result}")
			stats = file.last_analysis_stats

			print(f'''VirusTotal: {filename}
Безвредный: {stats["harmless"]}
Неподдерживаемый тип: {stats["type-unsupported"]}
Подозрительный: {stats["suspicious"]}
Отказ: {stats["failure"]}
Злонамеренный: {stats["malicious"]}
Безопасный: {stats["undetected"]}
		''')

		if result in signatures or result2 in signatures or result3 in signatures:
			end = perf_counter()
			total = end - start
			print(f'{Fore.RED}[!] Найдена угроза в файле {filename}!{Style.RESET_ALL}')

			if result in signatures:
				info = get_info_signature(result)
			elif result2 in signatures:
				info = get_info_signature(result2)
			elif result3 in signatures:
				info = get_info_signature(result3)
				
			print(info)

			if delete_file:
				os.remove(filename)
				print(f'{Fore.GREEN}[!] Файл {filename} удален!{Style.RESET_ALL}')

			print(f'Время работы: {(total):.07f}s')
		else:
			end = perf_counter()
			total = end - start
			print('[+] Угроз не найдено')
			print(f'Время работы: {(total):.07f}s')
	except FileNotFoundError:
		print(f'{Fore.RED}[!] Файл не найден{Style.RESET_ALL}')
	except PermissionError:
		print(f'{Fore.RED}[!] Ошибка прав доступа к файлу{Style.RESET_ALL}')

	print()

	return None
