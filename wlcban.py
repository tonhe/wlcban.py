#!/usr/bin/env python3
VERSION = 'v0.0.1'
# wlcban - Based on the bash script of the same name circa 2015
# Created by Tony Mattke on 6/26/18 
# Copyright 2018 Tony Mattke. All rights reserved.
# http://routerjockey.com tony@mattke.net http://twitter.com/tonhe
import os
import sys
import logging
import getpass
import ldap3
from netaddr import *
from paramiko import *
from paramiko_expect import SSHClientInteraction
# Global Variables
LDAP_DOMAIN = 'domain.local'
LDAP_BASE = 'DC=domain,DC=local'
LDAP_GROUP = "AD GROUP NAME" # What AD Group does the account need to be part of
WLCS = ['wlc01.domain.local','wlc02.domain.local','wlc03.domain.local'] # What WLCs are we configuring
PROMPT = "(.*) >" # WLC Prompt (for expect script) 
# Logging Config
logger=logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.setLevel(logging.DEBUG) # Uncomment to set logging to DEBUG
ALLOW_CONFIG = True # Used for testing 

def print_header ():
	print ("""
################################################################################
##
##  wlcban - aka the ban hammer""",VERSION,""" (python edition)
##
""")

def game_over(): # In the event of an issue... print a fun message and quit.
	print ('\n\n\n*** Houston, we have a problem. ***\n\nExiting now before we cause some real damaage!\n\nNotice: Some configuration changes may of been made.\nCheck the output above for more information.\n\n')
	print ("""
      ####    ##   #    # ######     ####  #    # ###### #####  
     #    #  #  #  ##  ## #         #    # #    # #      #    # 
     #      #    # # ## # #####     #    # #    # #####  #    # 
     #  ### ###### #    # #         #    # #    # #      #####  
     #    # #    # #    # #         #    #  #  #  #      #   #  
      ####  #    # #    # ######     ####    ##   ###### #    # \n\n\n""")
	quit()
    
def get_input(question, options): # string question, dict list of options. 
	while True:
		answer = str(input(question)).lower()
		if (answer == ""):
			try: 
				choice = options["default"]
			except: 
				print ("\n*** Please enter a valid option")
				continue
			else:
				logger.debug ("Default Option - returning " + choice )
				break
		elif (answer == "default"): # Unfortunately - I prevent "default" from ever being an option.
			logger.debug("Preventing Oddities - user entered hidden option (%s)" % (answer))
			print ("\n*** Please enter a valid option")
			continue
		else: 
			try:
				choice = options[answer] # if this fails, we know they didn't enter a valid option
				break
			except:
				logger.debug("%s not found in %s" % (answer, options))
				print ("\n*** Please enter a valid option")
				continue
	logger.debug ("Indexing %s - returning %s" % (answer, choice))
	return choice
	
def gather_user_info(): # Gather AD/LDAP Authentication Info & Verify Group Membership (Username and Password)
	print ("\nNotice: Use your %s Active Directory Username and Password" % LDAP_DOMAIN)
	while True:
		username = input("\nUsername [%s]: " % getpass.getuser())
		while not username:
			username = getpass.getuser()
		password = getpass.getpass()
		while not password:
			print ("\n*** Blank Passwords are not alowed.")
			password = getpass.getpass()
		ldap_username = "%s@%s" % (username, LDAP_DOMAIN)
		try: # Attempt to AuthN with this combo
			ldap_connection = ldap3.Connection(ldap3.Server(LDAP_DOMAIN, get_info=ldap3.ALL), user=ldap_username, password=password, auto_bind=True)
		except:
			print("\n*** LDAP Connection Error - try entering your creditials again...")
			continue
		else:
			logger.debug ("AuthN Success!! (%s)" % username )
			ldap_connection.search(LDAP_BASE, '(&(objectClass=person)(sAMAccountName=%s))' % username, attributes=['memberOf'] )
			groups = ldap_connection.entries[0]
			logger.debug(groups)
			locate = str(groups).find(LDAP_GROUP)
			logger.debug("STR Find Output - %s" % locate)
			if locate < 0: # if the LDAP_GROUP string isn't found, the find() will return -1
				print ("*** This account doesn't have permission to make changes to the WLC")	
				game_over()
			else:
				logger.debug ("AuthZ Success!! (%s)" % username )
				break
	return (username, password)
	
def do_expect(ic,es,st): # Repeatable Expect Script Actions -- Input: InteractiveExpectClient, ExpectString, SendText
	try:
		logger.debug("expecting (%s)" % es )
		ic.expect(es)
	except Exception as e:
		print ("*** Except script failure (%s)" % str(e))
		game_over()
	else:
		try:
			logger.debug('sending...')
			ic.send(st)
		except Exception as e:
			print ("*** Client Send failure (%s)" % str(e))
			game_over()
			
def display_config(mac_list,action,comment): # Display hosts to be configured, and generated config
	print ('\n\nHosts to configure')
	for host in WLCS:
		print ('\t' + host)
	print ('\nConfiguration to push')
	for address in mac_list:
		print ('\tconfig exclusionlist %s %s %s' % (action, address, comment))
	print ('\t save config')			
	
def main(): ############## Main
	print_header()
## MAC Address Loop
	action = get_input("\n\n Do you wish to add or delete MAC addresses from the ban list? (Add/delete): ", {"default":"add", "add":"add", "delete":"delete", "ad":"add", "del":"delete"})
	mac_list=[] 	
	print("\n Enter MAC addresses one at a time, use a blank line to end: \n")
	while True: 
		mac_input = str(input ()).replace(" ", "")
		logger.debug("Incoming MAC %s " % mac_input)
		try:
			new_mac = EUI(mac_input)
			new_mac.dialect = mac_unix_expanded
		except: 
			if mac_input == "": 
				break
			else: 
				print ("\n*** Invalid MAC Address... Try again")
		else: 
			mac_list.append(new_mac)
			logger.debug("Adding MAC address %s " % new_mac)
## Get Username and Password
	(client_user, client_password) = gather_user_info()	
## Get Ticket Number / Comment 
	logger.debug ("User %s sucessfully returned with password" % client_user)
	if action == "add": 
		comment = input ("\nEnter Ticket Number / Comment notes: ")
	else:
		comment = ""
	logger.debug ("Comment (%s)" % comment)
## Display Configuration 
	display_config(mac_list,action,comment)
## Are you ready? 
	print_header()
	ready = get_input("\n\n Are you ready to execute? (yes/no): ", {"yes":"yes", "no":"no"}) 
	if ready == "no": 
		print('\n\n*** Exiting - no changes made')
		quit()
## Execute 		
	for host in WLCS: # Loop through list of WLC's
		print ("\n> Connecting to %s..." % host)
		client = SSHClient()
		client.load_system_host_keys()
		client.set_missing_host_key_policy(AutoAddPolicy())
		try:
			client.connect(host, username=client_user, password=client_password)
		except Exception as e:
			print("*** Issue Connecting to WLC %s (%s)" % (host, str(e)) )
			game_over()
		except:
			print("*** Issue Connecting to WLC %s" % host )
			game_over()
		else: 
			with SSHClientInteraction(client, timeout=10, display=True) as interact: # Fire up Expect
				interact.send('')
				do_expect(interact, 'User:', client_user)
				do_expect(interact, '.assword:', client_password)
				for address in mac_list: # Loop through list of MAC Addresses 
					if ALLOW_CONFIG == True:
						do_expect(interact, PROMPT, 'config exclusionlist %s %s %s' % (action, address, comment))
				if ALLOW_CONFIG == True:
					do_expect(interact, PROMPT, "save config")
					do_expect(interact, "Are you sure.*", "y") 
			print ("> Closing connection to %s" % host )
			client.close()

if __name__ == "__main__": #############################################################
	main()
	print ('\n\n Success! - Changes complete')