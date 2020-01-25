#!/usr/local/bin/python3
# coding: utf-8


from os import path
from urllib import request
from json import loads as json_loads
from hashlib import md5
from terminaltables import AsciiTable
from colorama import Fore
from webbrowser import open as webbrowser_open


logo = (Fore.MAGENTA + r'''
  
┌───────────────────────────────────────────────────────────┐
│    ___    _   _____    ____  ________  ___________ __  ___│
│   /   |  / | / /   |  / __ \/ ____/ / / /  _/ ___//  |/  /│
│  / /| | /  |/ / /| | / /_/ / /   / /_/ // / \__ \/ /|_/ / │
│ / ___ |/ /|  / ___ |/ _, _/ /___/ __  // / ___/ / /  / /  │
│/_/  |_/_/ |_/_/  |_/_/ |_|\____/_/ /_/___//____/_/  /_/   │
│                                                           │
└───────────────────────────────────────────────────────────┘
           Created by N0t-Eth1ca1-Hac4r with ''' + Fore.RED + '''Love <3 ''' + Fore.MAGENTA + '''

   * Вы должны выбрать путь к файлу.
   * Проверяется только хеш файла на Virustotal.
   * Сам файл не будет отправлен.

    Лицензировано GNU LGPL (LGPL-3.0-only)')

	''' + Fore.RESET)

def main():

	
	def getFilemd5(filename):
	    hash_md5 = md5()
	    with open(filename, "rb") as f:
	        for chunk in iter(lambda: f.read(4096), b""):
	            hash_md5.update(chunk)
	    return hash_md5.hexdigest()


	file = input(Fore.CYAN + ' >>> Выберите файл: ' + Fore.RESET)
	if not path.exists(file):
		exit(Fore.RED + "[!] Файл " + file + " не найден!" + Fore.RESET)
	else:
		file_md5 = getFilemd5(file)

	
	virustotal = json_loads(request.urlopen('https://www.virustotal.com/ui/search?query=' + file_md5).read())

	
	detection = virustotal['data'][0]['attributes']['last_analysis_results']
	table_data = [
	    ['Scanner', 'Category']
	]
	for res in detection:
		engine   = detection[res]['engine_name']
		category = detection[res]['category']

		
		if category.lower() == "undetected":
			category = Fore.GREEN + category
		else:
			category = Fore.RED + category

		category += Fore.RESET
	
		table_data.append([engine, category])

	
	table = AsciiTable(table_data)
	print(table.table)

	
	detection = virustotal['data'][0]['attributes']['last_analysis_stats']
	print(
		"\n>> STATS:"
		"\n-*  Malicious   : " + str(detection['malicious'])  +
		"\n-*  Suspicious  : " + str(detection['suspicious']) +
		"\n-*  Harmless    : " + str(detection['harmless'])   +
		"\n-*  Undetected  : " + str(detection['undetected'])
		)

	
	if virustotal['data']:
		if input('\n [?] Открыть полный репорт от VirusTotal? (y/n)\n ---> ').lower() in ('y', 'yes'):
			webbrowser_open('https://www.virustotal.com/gui/file/' + file_md5 + '/detection')

if __name__ == '__main__':
	print(logo)
	main()
