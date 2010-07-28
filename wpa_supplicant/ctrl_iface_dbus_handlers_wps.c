/*
 * WPA Supplicant / dbus-based control interface (WPS)
 * Copyright (c) 2006, Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "wps_supplicant.h"
#include "ctrl_iface_dbus.h"
#include "ctrl_iface_dbus_handlers.h"

/**
 * wpas_dbus_iface_wps_pbc - Request credentials using WPS PBC method
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: A dbus message containing a UINT32 indicating success (1) or
 *          failure (0)
 *
 * Handler function for "wpsPbc" method call
 */
DBusMessage * wpas_dbus_iface_wps_pbc(DBusMessage *message,
				      struct wpa_supplicant *wpa_s)
{
	char *arg_bssid = NULL;
	u8 bssid[ETH_ALEN];
	int ret = 0;

	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &arg_bssid,
				   DBUS_TYPE_INVALID))
		return wpas_dbus_new_invalid_opts_error(message, NULL);

	if (!os_strcmp(arg_bssid, "any"))
		ret = wpas_wps_start_pbc(wpa_s, NULL);
	else if (!hwaddr_aton(arg_bssid, bssid))
		ret = wpas_wps_start_pbc(wpa_s, bssid);
	else {
		return wpas_dbus_new_invalid_opts_error(message,
							"Invalid BSSID");
	}

	if (ret < 0) {
		return dbus_message_new_error(message,
					      WPAS_ERROR_WPS_PBC_ERROR,
					      "Could not start PBC "
					      "negotiation");
	}

	return wpas_dbus_new_success_reply(message);
}


/**
 * wpas_dbus_iface_wps_pin - Establish the PIN number of the enrollee
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: A dbus message containing a UINT32 indicating success (1) or
 *          failure (0)
 *
 * Handler function for "wpsPin" method call
 */
DBusMessage * wpas_dbus_iface_wps_pin(DBusMessage *message,
				      struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	char *arg_bssid;
	char *pin = NULL;
	u8 bssid[ETH_ALEN], *_bssid = NULL;
	int ret = 0;

	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &arg_bssid,
				   DBUS_TYPE_STRING, &pin, DBUS_TYPE_INVALID))
		return wpas_dbus_new_invalid_opts_error(message, NULL);

	if (!os_strcmp(arg_bssid, "any"))
		_bssid = NULL;
	else if (!hwaddr_aton(arg_bssid, bssid))
		_bssid = bssid;
	else {
		return wpas_dbus_new_invalid_opts_error(message,
							"Invalid BSSID");
	}

	if (os_strlen(pin) > 0)
		ret = wpas_wps_start_pin(wpa_s, _bssid, pin);
	else
		ret = wpas_wps_start_pin(wpa_s, _bssid, NULL);

	if (ret < 0) {
		return dbus_message_new_error(message,
					      WPAS_ERROR_WPS_PIN_ERROR,
					      "Could not init PIN");
	}

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	if (ret == 0) {
		dbus_message_append_args(reply, DBUS_TYPE_STRING, &pin,
					 DBUS_TYPE_INVALID);
	} else {
		char npin[9];
        pin = npin;
		os_snprintf(npin, sizeof(npin), "%08d", ret);
		dbus_message_append_args(reply, DBUS_TYPE_STRING, &pin,
					 DBUS_TYPE_INVALID);
	}
	return reply;
}


/**
 * wpas_dbus_iface_wps_reg - Request credentials using the PIN of the AP
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: A dbus message containing a UINT32 indicating success (1) or
 *          failure (0)
 *
 * Handler function for "wpsReg" method call
 */
DBusMessage * wpas_dbus_iface_wps_reg(DBusMessage *message,
				      struct wpa_supplicant *wpa_s)
{
	char *arg_bssid;
	char *pin = NULL;
	u8 bssid[ETH_ALEN];
	int ret = 0;

	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &arg_bssid,
				   DBUS_TYPE_STRING, &pin, DBUS_TYPE_INVALID))
		return wpas_dbus_new_invalid_opts_error(message, NULL);

	if (!os_strcmp(arg_bssid, "any"))
		ret = wpas_wps_start_reg(wpa_s, NULL, pin);
	else if (!hwaddr_aton(arg_bssid, bssid))
		ret = wpas_wps_start_reg(wpa_s, bssid, pin);
	else {
		return wpas_dbus_new_invalid_opts_error(message,
							"Invalid BSSID");
	}

	if (ret < 0) {
		return dbus_message_new_error(message,
					      WPAS_ERROR_WPS_PBC_ERROR,
					      "Could not request credentials");
	}

	return wpas_dbus_new_success_reply(message);
}


/**
 * wpas_dbus_iface_wps_get_process_credentials - Check if credentials are processed
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: DBus message with a boolean on success or DBus error on failure
 *
 * Getter for "ProcessCredentials" property. Returns returned boolean will be
 * true if wps_cred_processing configuration field is not equal to 1 or false
 * if otherwise.
 */
DBusMessage * wpas_dbus_iface_wps_get_process_credentials(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	dbus_bool_t process = (wpa_s->conf->wps_cred_processing != 1);
	DBusMessage *reply = NULL;
	DBusMessageIter iter, variant_iter;

	reply = dbus_message_new_method_return(message);
	if (reply != NULL) {
		dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN,
					 &process, DBUS_TYPE_INVALID);
		
	} else {
		wpa_printf(MSG_ERROR, "dbus: wpas_dbus_get_process_credentials:"
			   " out of memory to return property value");
		reply = dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY,
					       NULL);
	}

	return reply;
}


/**
 * wpas_dbus_iface_wps_set_process_credentials - Set credentials_processed conf param
 * @message: Pointer to incoming dbus message
 * @wpa_s: %wpa_supplicant data structure
 * Returns: NULL on success or DBus error on failure
 *
 * Setter for "ProcessCredentials" property. Sets credentials_processed on 2
 * if boolean argument is true or on 1 if otherwise.
 */
DBusMessage * wpas_dbus_iface_wps_set_process_credentials(
	DBusMessage *message, struct wpa_supplicant *wpa_s)
{
	DBusMessage *reply = NULL;
	dbus_bool_t process_credentials;

	if (!dbus_message_get_args(message, NULL,
				   DBUS_TYPE_BOOLEAN, &process_credentials,
				   DBUS_TYPE_INVALID)) {
		return wpas_dbus_new_invalid_opts_error(message, NULL);
	}

	wpa_s->conf->wps_cred_processing = (process_credentials ? 2 : 1);

	return wpas_dbus_new_success_reply(message);
}
