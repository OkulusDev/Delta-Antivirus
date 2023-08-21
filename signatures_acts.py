#!/usr/bin/python3
# -*- coding:utf-8 -*-
"""Простой антивирус 'Delta' на Python
Разработчик: Okulus Dev (C) 2023
Лицензия: GNU GPL v3"""
import json
from config import signature_resources, signature_resource_info


def add_signatures(new_signatures: dict) -> None:
	with open(signature_resource_info, 'r') as file:
		signatures_info = json.load(file)

	for signature in new_signatures:
		signatures_info['name'] = new_signatures['name']
		signatures_info['desc'] = new_signatures['desc']
		signatures_info['date'] = new_signatures['date']

	with open(signature_resource_info, 'a') as file:
		json.dump(signatures_info, file, indent=4)

	return None


def rewrite_signatures(signatures: dict) -> bool:
	try:
		with open(signature_resource_info, 'w') as file:
			json.dump(signatures, file, indent=4)
	except Exception as e:
		return False
	else:
		return True


def get_info_signature(signature: str) -> str:
	with open(signature_resource_info, 'r') as file:
		signatures_info = json.load(file)

	try:
		signature_info = f'''Сигнатура: {signature}
Название угрозы: {signatures_info[signature]["name"]}
Описание угрозы: {signatures_info[signature]["desc"]}
Дата обнаружения угроза: {signatures_info[signature]["date"]}'''
	except IndexError:
		signature_info = f'По сигнатуре {signature} еще нету информации в наших базах данных'
	finally:
		return signature_info
