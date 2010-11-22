/*
 * WPA Supplicant - driver interaction with Ralink Wireless Client
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2007, Snowpin Lee <snowpin_lee@ralinktech.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 */

#include "includes.h"
#include <sys/ioctl.h>

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "l2_packet/l2_packet.h"
#include "eloop.h"
#include "ieee802_11_defs.h"
#include "priv_netlink.h"
#include "driver_ralink.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"
#include "../wpa_supplicant/config.h"

static void wpa_driver_ralink_scan_timeout(void *eloop_ctx, void *timeout_ctx);

#define MAX_SSID_LEN 32
BOOLEAN	bAddWepKey = FALSE;

struct wpa_driver_ralink_data {
	void *ctx;
	int ioctl_sock;
	int event_sock;
	char ifname[IFNAMSIZ + 1];
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	u8 *assoc_resp_ies;
	size_t assoc_resp_ies_len;
	int no_of_pmkid;
	struct ndis_pmkid_entry *pmkid;
	int we_version_compiled;
	int ap_scan;
	u8 g_driver_down;
};

static int ralink_set_oid(struct wpa_driver_ralink_data *drv,
			  unsigned short oid, char *data, int len)
{
	char *buf;
	struct iwreq iwr;

	buf = os_zalloc(len);
	if (buf == NULL)
		return -1;
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.flags = oid;
	iwr.u.data.flags |= OID_GET_SET_TOGGLE;

	if (data)
		os_memcpy(buf, data, len);

	iwr.u.data.pointer = (caddr_t) buf;
	iwr.u.data.length = len;

	if (ioctl(drv->ioctl_sock, RT_PRIV_IOCTL, &iwr) < 0) {
		wpa_printf(MSG_DEBUG, "%s: oid=0x%x len (%d) failed",
			   __func__, oid, len);
		os_free(buf);
		return -1;
	}
	os_free(buf);
	return 0;
}

static int
ralink_get_new_driver_flag(struct wpa_driver_ralink_data *drv)
{
	struct iwreq iwr;
	UCHAR enabled = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.pointer = (UCHAR*) &enabled;
	iwr.u.data.flags = RT_OID_NEW_DRIVER;

	if (ioctl(drv->ioctl_sock, RT_PRIV_IOCTL, &iwr) < 0) {
		wpa_printf(MSG_DEBUG, "%s: failed", __func__);
		return 0;
	}

	return (enabled == 1) ? 1 : 0;
}

static int wpa_driver_ralink_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCGIWAP, &iwr) < 0) {
		perror("ioctl[SIOCGIWAP]");
		ret = -1;
	}
	os_memcpy(bssid, iwr.u.ap_addr.sa_data, ETH_ALEN);

	return ret;
}

static int wpa_driver_ralink_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_ralink_data *drv = priv;
#if 0
	struct wpa_supplicant *wpa_s = drv->ctx;
	struct wpa_ssid *entry;
#endif
	int ssid_len;
	u8 bssid[ETH_ALEN];
	u8 ssid_str[MAX_SSID_LEN];
	struct iwreq iwr;
#if 0
	int result = 0;
#endif
	int ret = 0;
#if 0
	BOOLEAN	ieee8021x_mode = FALSE;
	BOOLEAN ieee8021x_required_key = FALSE;
#endif

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.essid.pointer = (caddr_t) ssid;
	iwr.u.essid.length = 32;

	if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCGIWESSID]");
		ret = -1;
	} else
		ret = iwr.u.essid.length;

	if (ret <= 0)
		return ret;

	ssid_len = ret;
	os_memset(ssid_str, 0, MAX_SSID_LEN);
	os_memcpy(ssid_str, ssid, ssid_len);

	if (drv->ap_scan == 0) {
		/* Read BSSID form driver */
		if (wpa_driver_ralink_get_bssid(priv, bssid) < 0) {
			wpa_printf(MSG_WARNING, "Could not read BSSID from "
				   "driver.");
			return ret;
		}

#if 0
		entry = wpa_s->conf->ssid;
		while (entry) {
			if (!entry->disabled && ssid_len == entry->ssid_len &&
			    os_memcmp(ssid_str, entry->ssid, ssid_len) == 0 &&
			    (!entry->bssid_set ||
			     os_memcmp(bssid, entry->bssid, ETH_ALEN) == 0)) {
				/* match the config of driver */
				result = 1;
				break;
			}
			entry = entry->next;
		}

		if (result) {
			wpa_printf(MSG_DEBUG, "Ready to set 802.1x mode and "
				   "ieee_required_keys parameters to driver");

			/* set 802.1x mode and ieee_required_keys parameter */
			if (entry->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
				if ((entry->eapol_flags & (EAPOL_FLAG_REQUIRE_KEY_UNICAST | EAPOL_FLAG_REQUIRE_KEY_BROADCAST)))
						ieee8021x_required_key = TRUE;
				ieee8021x_mode = TRUE;
			}

			if (ralink_set_oid(drv, OID_802_11_SET_IEEE8021X, (char *) &ieee8021x_mode, sizeof(BOOLEAN)) < 0)
			{
				wpa_printf(MSG_DEBUG, "RALINK: Failed to set OID_802_11_SET_IEEE8021X(%d)", (int) ieee8021x_mode);
			}
			else
			{
				wpa_printf(MSG_DEBUG, "ieee8021x_mode is %s", ieee8021x_mode ? "TRUE" : "FALSE");
			}

			if (ralink_set_oid(drv, OID_802_11_SET_IEEE8021X_REQUIRE_KEY, (char *) &ieee8021x_required_key, sizeof(BOOLEAN)) < 0)
			{
				wpa_printf(MSG_DEBUG, "ERROR: Failed to set OID_802_11_SET_IEEE8021X_REQUIRE_KEY(%d)", (int) ieee8021x_required_key);
			}
			else
			{
				wpa_printf(MSG_DEBUG, "ieee8021x_required_key is %s and eapol_flag(%d)", ieee8021x_required_key ? "TRUE" : "FALSE",
																								entry->eapol_flags);
			}
		}
#endif
	}

	return ret;
}

static int wpa_driver_ralink_set_ssid(struct wpa_driver_ralink_data *drv,
				      const u8 *ssid, size_t ssid_len)
{
	NDIS_802_11_SSID *buf;
	int ret = 0;
	struct iwreq iwr;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	buf = os_zalloc(sizeof(NDIS_802_11_SSID));
	if (buf == NULL)
		return -1;
	os_memset(buf, 0, sizeof(buf));
	buf->SsidLength = ssid_len;
	os_memcpy(buf->Ssid, ssid, ssid_len);
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	iwr.u.data.flags = OID_802_11_SSID;
	iwr.u.data.flags |= OID_GET_SET_TOGGLE;
	iwr.u.data.pointer = (caddr_t) buf;
	iwr.u.data.length = sizeof(NDIS_802_11_SSID);

	if (ioctl(drv->ioctl_sock, RT_PRIV_IOCTL, &iwr) < 0) {
		perror("ioctl[RT_PRIV_IOCTL] -- OID_802_11_SSID");
		ret = -1;
	}
	os_free(buf);
	return ret;
}

static void wpa_driver_ralink_event_pmkid(struct wpa_driver_ralink_data *drv,
					  const u8 *data, size_t data_len)
{
	NDIS_802_11_PMKID_CANDIDATE_LIST *pmkid;
	size_t i;
	union wpa_event_data event;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (data_len < 8) {
		wpa_printf(MSG_DEBUG, "RALINK: Too short PMKID Candidate List "
			   "Event (len=%lu)", (unsigned long) data_len);
		return;
	}
	pmkid = (NDIS_802_11_PMKID_CANDIDATE_LIST *) data;
	wpa_printf(MSG_DEBUG, "RALINK: PMKID Candidate List Event - Version %d"
		   " NumCandidates %d",
		   (int) pmkid->Version, (int) pmkid->NumCandidates);

	if (pmkid->Version != 1) {
		wpa_printf(MSG_DEBUG, "RALINK: Unsupported PMKID Candidate "
			   "List Version %d", (int) pmkid->Version);
		return;
	}

	if (data_len < 8 + pmkid->NumCandidates * sizeof(PMKID_CANDIDATE)) {
		wpa_printf(MSG_DEBUG, "RALINK: PMKID Candidate List "
			   "underflow");

		return;
	}



	os_memset(&event, 0, sizeof(event));
	for (i = 0; i < pmkid->NumCandidates; i++) {
		PMKID_CANDIDATE *p = &pmkid->CandidateList[i];
		wpa_printf(MSG_DEBUG, "RALINK: %lu: " MACSTR " Flags 0x%x",
			   (unsigned long) i, MAC2STR(p->BSSID),
			   (int) p->Flags);
		os_memcpy(event.pmkid_candidate.bssid, p->BSSID, ETH_ALEN);
		event.pmkid_candidate.index = i;
		event.pmkid_candidate.preauth =
			p->Flags & NDIS_802_11_PMKID_CANDIDATE_PREAUTH_ENABLED;
		wpa_supplicant_event(drv->ctx, EVENT_PMKID_CANDIDATE,
				     &event);
	}
}

static int wpa_driver_ralink_set_pmkid(struct wpa_driver_ralink_data *drv)
{
	int len, count, i, ret;
	struct ndis_pmkid_entry *entry;
	NDIS_802_11_PMKID *p;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	count = 0;
	entry = drv->pmkid;
	while (entry) {
		count++;
		if (count >= drv->no_of_pmkid)
			break;
		entry = entry->next;
	}
	len = 8 + count * sizeof(BSSID_INFO);
	p = os_zalloc(len);
	if (p == NULL)
		return -1;
	p->Length = len;
	p->BSSIDInfoCount = count;
	entry = drv->pmkid;
	for (i = 0; i < count; i++) {
		os_memcpy(&p->BSSIDInfo[i].BSSID, entry->bssid, ETH_ALEN);
		os_memcpy(&p->BSSIDInfo[i].PMKID, entry->pmkid, 16);
		entry = entry->next;
	}
	wpa_hexdump(MSG_MSGDUMP, "NDIS: OID_802_11_PMKID",
		    (const u8 *) p, len);
	ret = ralink_set_oid(drv, OID_802_11_PMKID, (char *) p, len);
	os_free(p);
	return ret;
}

static int wpa_driver_ralink_add_pmkid(void *priv, const u8 *bssid,
				       const u8 *pmkid)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct ndis_pmkid_entry *entry, *prev;

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (drv->no_of_pmkid == 0)
		return 0;

	prev = NULL;
	entry = drv->pmkid;
	while (entry) {
		if (os_memcmp(entry->bssid, bssid, ETH_ALEN) == 0)
			break;
		prev = entry;
		entry = entry->next;
	}

	if (entry) {
		/* Replace existing entry for this BSSID and move it into the
		 * beginning of the list. */
		os_memcpy(entry->pmkid, pmkid, 16);
		if (prev) {
			prev->next = entry->next;
			entry->next = drv->pmkid;
			drv->pmkid = entry;
		}
	} else {
		entry = os_malloc(sizeof(*entry));
		if (entry) {
			os_memcpy(entry->bssid, bssid, ETH_ALEN);
			os_memcpy(entry->pmkid, pmkid, 16);
			entry->next = drv->pmkid;
			drv->pmkid = entry;
		}
	}

	return wpa_driver_ralink_set_pmkid(drv);
}


static int wpa_driver_ralink_remove_pmkid(void *priv, const u8 *bssid,
					  const u8 *pmkid)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct ndis_pmkid_entry *entry, *prev;

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (drv->no_of_pmkid == 0)
		return 0;

	entry = drv->pmkid;
	prev = NULL;
	drv->pmkid = NULL;
	while (entry) {
		if (os_memcmp(entry->bssid, bssid, ETH_ALEN) == 0 &&
		    os_memcmp(entry->pmkid, pmkid, 16) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				drv->pmkid = entry->next;
			os_free(entry);
			break;
		}
		prev = entry;
		entry = entry->next;
	}
	return wpa_driver_ralink_set_pmkid(drv);
}


static int wpa_driver_ralink_flush_pmkid(void *priv)
{
	struct wpa_driver_ralink_data *drv = priv;
	NDIS_802_11_PMKID p;
	struct ndis_pmkid_entry *pmkid, *prev;

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (drv->no_of_pmkid == 0)
		return 0;

	pmkid = drv->pmkid;
	drv->pmkid = NULL;
	while (pmkid) {
		prev = pmkid;
		pmkid = pmkid->next;
		os_free(prev);
	}

	os_memset(&p, 0, sizeof(p));
	p.Length = 8;
	p.BSSIDInfoCount = 0;
	wpa_hexdump(MSG_MSGDUMP, "NDIS: OID_802_11_PMKID (flush)",
		    (const u8 *) &p, 8);
	return ralink_set_oid(drv, OID_802_11_PMKID, (char *) &p, 8);
}

static void
wpa_driver_ralink_event_wireless_custom(struct wpa_driver_ralink_data *drv,
					void *ctx, char *custom)
{
	union wpa_event_data data;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	wpa_printf(MSG_DEBUG, "Custom wireless event: '%s'", custom);

	os_memset(&data, 0, sizeof(data));
	/* Host AP driver */
	if (os_strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
		/* receive a MICFAILURE report */
		data.michael_mic_failure.unicast =
			os_strstr(custom, " unicast") != NULL;
		/* TODO: parse parameters(?) */
		wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE, &data);
	} else if (os_strncmp(custom, "ASSOCINFO_ReqIEs=", 17) == 0) {
		/* receive assoc. req. IEs */
		char *spos;
		int bytes;

		spos = custom + 17;
		/*get IE's length */
		/*
		 * bytes = strlen(spos); ==> bug, bytes may less than original
		 * size by using this way to get size. snowpin 20070312
		 * if (!bytes)
		 *	return;
		 */
		bytes = drv->assoc_req_ies_len;

		data.assoc_info.req_ies = os_malloc(bytes);
		if (data.assoc_info.req_ies == NULL)
			return;

		data.assoc_info.req_ies_len = bytes;
		os_memcpy(data.assoc_info.req_ies, spos, bytes);

		/* skip the '\0' byte */
		spos += bytes + 1;

		data.assoc_info.resp_ies = NULL;
		data.assoc_info.resp_ies_len = 0;

		if (os_strncmp(spos, " RespIEs=", 9) == 0) {
			/* receive assoc. resp. IEs */
			spos += 9;
			/* get IE's length */
			bytes = os_strlen(spos);
			if (!bytes)
				goto done;


			data.assoc_info.resp_ies = os_malloc(bytes);
			if (data.assoc_info.resp_ies == NULL)
				goto done;

			data.assoc_info.resp_ies_len = bytes;
			os_memcpy(data.assoc_info.resp_ies, spos, bytes);
		}

		wpa_supplicant_event(ctx, EVENT_ASSOCINFO, &data);

		/* free allocated memory */
	done:
		os_free(data.assoc_info.resp_ies);
		os_free(data.assoc_info.req_ies);
	}
}

static void
wpa_driver_ralink_event_wireless(struct wpa_driver_ralink_data *drv,
				 void *ctx, char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf, *assoc_info_buf, *info_pos;
#if 0
	BOOLEAN ieee8021x_required_key = FALSE;
#endif

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	assoc_info_buf = info_pos = NULL;
	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		wpa_printf(MSG_DEBUG, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;

		if (drv->we_version_compiled > 18 && iwe->cmd == IWEVCUSTOM) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			os_memcpy(dpos, pos + IW_EV_LCP_LEN,
				  sizeof(struct iw_event) - dlen);
		} else {
			os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = os_malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;
			os_memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';

#if 0
			if (drv->ap_scan == 1) {
				if ((iwe->u.data.flags == RT_ASSOC_EVENT_FLAG)
				    || (iwe->u.data.flags ==
					RT_REQIE_EVENT_FLAG) ||
				    (iwe->u.data.flags == RT_RESPIE_EVENT_FLAG)
				    || (iwe->u.data.flags ==
					RT_ASSOCINFO_EVENT_FLAG)) {
					if (drv->scanning_done == 0) {
						os_free(buf);
						return;
					}
				}
			}
#endif

			if (iwe->u.data.flags == RT_ASSOC_EVENT_FLAG) 
			{
				wpa_supplicant_event(ctx, EVENT_ASSOC, NULL);				
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive ASSOCIATED_EVENT !!!");
			} else if (iwe->u.data.flags == RT_REQIE_EVENT_FLAG) {
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive ReqIEs !!!");
				drv->assoc_req_ies =
					os_malloc(iwe->u.data.length);
				if (drv->assoc_req_ies == NULL) {
					os_free(buf);
					return;
				}

				drv->assoc_req_ies_len = iwe->u.data.length;
				os_memcpy(drv->assoc_req_ies, custom,
					  iwe->u.data.length);
			} else if (iwe->u.data.flags == RT_RESPIE_EVENT_FLAG) {
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive RespIEs !!!");
				drv->assoc_resp_ies =
					os_malloc(iwe->u.data.length);
				if (drv->assoc_resp_ies == NULL) {
					os_free(drv->assoc_req_ies);
					drv->assoc_req_ies = NULL;
					os_free(buf);
					return;
				}

				drv->assoc_resp_ies_len = iwe->u.data.length;
				os_memcpy(drv->assoc_resp_ies, custom,
					  iwe->u.data.length);
			} else if (iwe->u.data.flags ==
				   RT_ASSOCINFO_EVENT_FLAG) {
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive ASSOCINFO_EVENT !!!");

				assoc_info_buf =
					os_zalloc(drv->assoc_req_ies_len +
						  drv->assoc_resp_ies_len + 1);

				if (assoc_info_buf == NULL) {
					os_free(drv->assoc_req_ies);
					drv->assoc_req_ies = NULL;
					os_free(drv->assoc_resp_ies);
					drv->assoc_resp_ies = NULL;
					os_free(buf);
					return;
				}

				if (drv->assoc_req_ies) {
					os_memcpy(assoc_info_buf,
						  drv->assoc_req_ies,
						  drv->assoc_req_ies_len);
				}
				info_pos = assoc_info_buf +
					drv->assoc_req_ies_len;
				if (drv->assoc_resp_ies) {
					os_memcpy(info_pos,
						  drv->assoc_resp_ies,
						  drv->assoc_resp_ies_len);
				}
				assoc_info_buf[drv->assoc_req_ies_len +
					       drv->assoc_resp_ies_len] = '\0';
				wpa_driver_ralink_event_wireless_custom(
					drv, ctx, assoc_info_buf);
				os_free(drv->assoc_req_ies);
				drv->assoc_req_ies = NULL;
				os_free(drv->assoc_resp_ies);
				drv->assoc_resp_ies = NULL;
				os_free(assoc_info_buf);
			} else if (iwe->u.data.flags == RT_DISASSOC_EVENT_FLAG)
			{
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive DISASSOCIATED_EVENT !!!");
				wpa_supplicant_event(ctx, EVENT_DISASSOC,
						     NULL);
			} else if (iwe->u.data.flags == RT_PMKIDCAND_FLAG) {
				wpa_printf(MSG_DEBUG, "Custom wireless event: "
					   "receive PMKIDCAND_EVENT !!!");
				wpa_driver_ralink_event_pmkid(
					drv, (const u8 *) custom,
					iwe->u.data.length);
			} else if (iwe->u.data.flags == RT_INTERFACE_DOWN) {
				drv->g_driver_down = 1;
			} 
			else if (iwe->u.data.flags == RT_INTERFACE_UP) 
			{
				union wpa_event_data event;
                int enable_wpa_supplicant = 0;
                drv->g_driver_down = 0;
                os_memset(&event, 0, sizeof(event));
                os_snprintf(event.interface_status.ifname,
		                    sizeof(event.interface_status.ifname), "%s", drv->ifname);

                event.interface_status.ievent = EVENT_INTERFACE_ADDED;
                wpa_supplicant_event(ctx, EVENT_INTERFACE_STATUS, &event);

                if (drv->ap_scan == 1)
                    enable_wpa_supplicant = 1;
                else
                    enable_wpa_supplicant = 2;
                // trigger driver support wpa_supplicant
            	if (ralink_set_oid(drv, RT_OID_WPA_SUPPLICANT_SUPPORT, (PCHAR) &enable_wpa_supplicant, sizeof(UCHAR)) < 0)
            	{
            		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
            			   "RT_OID_WPA_SUPPLICANT_SUPPORT(%d)",
            			   (int) enable_wpa_supplicant);
                    printf("********************************************\n");
                    printf("*                                          *\n");
                    printf("*  Driver doesn't support Wpa_supplicant!!  \n");
                    printf("*                                          *\n");
                    printf("********************************************\n");
            	}
			} else {
				wpa_driver_ralink_event_wireless_custom(
					drv, ctx, buf);
			}
			os_free(buf);
			break;
		}

		pos += iwe->len;
	}
}

static void
wpa_driver_ralink_event_rtm_newlink(struct wpa_driver_ralink_data *drv,
				    void *ctx, struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (len < (int) sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);
	wpa_hexdump(MSG_DEBUG, "ifi: ", (u8 *) ifi, sizeof(struct ifinfomsg));

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	wpa_printf(MSG_DEBUG, "attrlen=%d", attrlen);
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);
	wpa_hexdump(MSG_DEBUG, "attr1: ", (u8 *) attr, sizeof(struct rtattr));
	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	wpa_hexdump(MSG_DEBUG, "attr2: ", (u8 *)attr,rta_len);
	while (RTA_OK(attr, attrlen)) {
		wpa_printf(MSG_DEBUG, "rta_type=%02x\n", attr->rta_type);
		if (attr->rta_type == IFLA_WIRELESS) {
			wpa_driver_ralink_event_wireless(
				drv, ctx,
				((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
		wpa_hexdump(MSG_DEBUG, "attr3: ",
			    (u8 *) attr, sizeof(struct rtattr));
	}
}

static void wpa_driver_ralink_event_receive(int sock, void *ctx,
					    void *sock_ctx)
{
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);

	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *) buf;
	wpa_hexdump(MSG_DEBUG, "h: ", (u8 *)h, h->nlmsg_len);

	while (left >= (int) sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			wpa_printf(MSG_DEBUG, "Malformed netlink message: "
				   "len=%d left=%d plen=%d", len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			wpa_driver_ralink_event_rtm_newlink(ctx, sock_ctx, h,
							    plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%d extra bytes in the end of netlink "
			   "message", left);
	}

}

static int
ralink_get_we_version_compiled(struct wpa_driver_ralink_data *drv)
{
	struct iwreq iwr;
	UINT we_version_compiled = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &we_version_compiled;
	iwr.u.data.flags = RT_OID_WE_VERSION_COMPILED;

	if (ioctl(drv->ioctl_sock, RT_PRIV_IOCTL, &iwr) < 0) {
		wpa_printf(MSG_DEBUG, "%s: failed", __func__);
		return -1;
	}

	drv->we_version_compiled = we_version_compiled;

	return 0;
}

static int
ralink_set_iface_flags(void *priv, int dev_up)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct ifreq ifr;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (drv->ioctl_sock < 0)
		return -1;

	os_memset(&ifr, 0, sizeof(ifr));
	os_snprintf(ifr.ifr_name, IFNAMSIZ, "%s", drv->ifname);

	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}

	return 0;
}

static void * wpa_driver_ralink_init(void *ctx, const char *ifname)
{
	int s;
	struct wpa_driver_ralink_data *drv;
	struct ifreq ifr;
	struct sockaddr_nl local;
	UCHAR enable_wpa_supplicant = 0;
	struct wpa_supplicant *_wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return NULL;
	}
	/* do it */
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		perror(ifr.ifr_name);
		return NULL;
	}

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;

	drv->ctx = ctx;
	drv->ap_scan = _wpa_s->conf->ap_scan;
	wpa_printf(MSG_DEBUG, "%s - drv->ap_scan = %d\n", __FUNCTION__, drv->ap_scan);
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->ioctl_sock = s;
	drv->g_driver_down = 0;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		close(drv->ioctl_sock);
		os_free(drv);
		return NULL;
	}

	os_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;

	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		close(drv->ioctl_sock);
		os_free(drv);
		return NULL;
	}

	eloop_register_read_sock(s, wpa_driver_ralink_event_receive, drv, ctx);
	drv->event_sock = s;
	drv->no_of_pmkid = 4; /* Number of PMKID saved supported */

	ralink_set_iface_flags(drv, 1);	/* mark up during setup */
	ralink_get_we_version_compiled(drv);
	wpa_driver_ralink_flush_pmkid(drv);

	if (drv->ap_scan == 1)
		enable_wpa_supplicant = 1;
	else
		enable_wpa_supplicant = 2;
	/* trigger driver support wpa_supplicant */
	if (ralink_set_oid(drv, RT_OID_WPA_SUPPLICANT_SUPPORT,
			   (PCHAR) &enable_wpa_supplicant, sizeof(UCHAR)) < 0)
	{
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "RT_OID_WPA_SUPPLICANT_SUPPORT(%d)",
			   (int) enable_wpa_supplicant);
		wpa_printf(MSG_ERROR, "RALINK: Driver does not support "
			   "wpa_supplicant");
		close(s);
		close(drv->ioctl_sock);
		os_free(drv);
		return NULL;
	}

	return drv;
}

static void wpa_driver_ralink_deinit(void *priv)
{
	struct wpa_driver_ralink_data *drv = priv;
	UCHAR enable_wpa_supplicant;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	enable_wpa_supplicant = 0;

	if (drv->g_driver_down == 0) {
		/* trigger driver disable wpa_supplicant support */
		if (ralink_set_oid(drv, RT_OID_WPA_SUPPLICANT_SUPPORT,
				   (char *) &enable_wpa_supplicant,
				   sizeof(BOOLEAN)) < 0) {
			wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
				   "RT_OID_WPA_SUPPLICANT_SUPPORT(%d)",
				   (int) enable_wpa_supplicant);
		}

		wpa_driver_ralink_flush_pmkid(drv);

		sleep(1);
		//ralink_set_iface_flags(drv, 0);
	}

	eloop_cancel_timeout(wpa_driver_ralink_scan_timeout, drv, drv->ctx);
	eloop_unregister_read_sock(drv->event_sock);
	close(drv->event_sock);
	close(drv->ioctl_sock);
	os_free(drv);
}

static void wpa_driver_ralink_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_ralink_data *drv = eloop_ctx;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);

}

static int wpa_driver_ralink_scan(void *priv, const u8 *ssid, size_t ssid_len)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (ssid_len > IW_ESSID_MAX_SIZE) {
		wpa_printf(MSG_DEBUG, "%s: too long SSID (%lu)",
			   __FUNCTION__, (unsigned long) ssid_len);
		return -1;
	}

	/* wpa_driver_ralink_set_ssid(drv, ssid, ssid_len); */

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCSIWSCAN, &iwr) < 0) {
		perror("ioctl[SIOCSIWSCAN]");
		ret = -1;
	}

	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	eloop_cancel_timeout(wpa_driver_ralink_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(4, 0, wpa_driver_ralink_scan_timeout, drv,
			       drv->ctx);

	return ret;
}

static u8 * wpa_driver_ralink_giwscan(struct wpa_driver_ralink_data *drv, size_t *len)
{
	struct iwreq iwr;
	u8 *res_buf;
	size_t res_buf_len = IW_SCAN_MAX_DATA;

	for (;;) {
		res_buf = os_malloc(res_buf_len);
		if (res_buf == NULL) {
			return NULL;
		}
		os_memset(&iwr, 0, sizeof(iwr));
		os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
		iwr.u.data.pointer = res_buf;
		iwr.u.data.length = res_buf_len;
		if (ioctl(drv->ioctl_sock, SIOCGIWSCAN, &iwr) == 0) {
			break;
		}
		if (errno == E2BIG && res_buf_len < 65535) {
			os_free(res_buf);
			res_buf = NULL;
			res_buf_len *= 2;
			if (res_buf_len > 65535)
				res_buf_len = 65535; /* 16-bit length field */
			wpa_printf(MSG_DEBUG, "Scan results did not fit - "
				   "trying larger buffer (%lu bytes)",
				   (unsigned long) res_buf_len);
		} else {
			perror("ioctl[SIOCGIWSCAN]");
			os_free(res_buf);
			return NULL;
		}
	}
	if (iwr.u.data.length > res_buf_len) {
		os_free(res_buf);
		return NULL;
	}
	*len = iwr.u.data.length;
	return res_buf;
}


/*
 * Data structure for collecting ralink scan results. This is needed to allow
 * the various methods of reporting IEs to be combined into a single IE buffer.
 */
struct ralink_scan_data {
	struct wpa_scan_res res;
	u8 *ie;
	size_t ie_len;
	u8 ssid[32];
	size_t ssid_len;
	int maxrate;
};


static void ralink_get_scan_mode(struct iw_event *iwe,
			       struct ralink_scan_data *res)
{
	if (iwe->u.mode == IW_MODE_ADHOC)
		res->res.caps |= IEEE80211_CAP_IBSS;
	else if (iwe->u.mode == IW_MODE_MASTER || iwe->u.mode == IW_MODE_INFRA)
		res->res.caps |= IEEE80211_CAP_ESS;
}


static void ralink_get_scan_ssid(struct iw_event *iwe,
			       struct ralink_scan_data *res, char *custom,
			       char *end)
{
	int ssid_len = iwe->u.essid.length;
	if (custom + ssid_len > end)
		return;
	if (iwe->u.essid.flags &&
	    ssid_len > 0 &&
	    ssid_len <= IW_ESSID_MAX_SIZE) {
		os_memcpy(res->ssid, custom, ssid_len);
		res->ssid_len = ssid_len;
	}
}


static void ralink_get_scan_freq(struct iw_event *iwe,
			       struct ralink_scan_data *res)
{
	int divi = 1000000, i;

	if (iwe->u.freq.e == 0) {
		/*
		 * Some drivers do not report frequency, but a channel.
		 * Try to map this to frequency by assuming they are using
		 * IEEE 802.11b/g.  But don't overwrite a previously parsed
		 * frequency if the driver sends both frequency and channel,
		 * since the driver may be sending an A-band channel that we
		 * don't handle here.
		 */

		if (res->res.freq)
			return;

		if (iwe->u.freq.m >= 1 && iwe->u.freq.m <= 13) {
			res->res.freq = 2407 + 5 * iwe->u.freq.m;
			return;
		} else if (iwe->u.freq.m == 14) {
			res->res.freq = 2484;
			return;
		}
	}

	if (iwe->u.freq.e > 6) {
		wpa_printf(MSG_DEBUG, "Invalid freq in scan results (BSSID="
			   MACSTR " m=%d e=%d)",
			   MAC2STR(res->res.bssid), iwe->u.freq.m,
			   iwe->u.freq.e);
		return;
	}

	for (i = 0; i < iwe->u.freq.e; i++)
		divi /= 10;
	res->res.freq = iwe->u.freq.m / divi;
}


static void ralink_get_scan_qual(struct iw_event *iwe,
			       struct ralink_scan_data *res)
{
	res->res.qual = iwe->u.qual.qual;
	res->res.noise = iwe->u.qual.noise;
	res->res.level = iwe->u.qual.level;
}


static void ralink_get_scan_encode(struct iw_event *iwe,
				 struct ralink_scan_data *res)
{
	if (!(iwe->u.data.flags & IW_ENCODE_DISABLED))
		res->res.caps |= IEEE80211_CAP_PRIVACY;
}

static void ralink_get_scan_iwevgenie(struct iw_event *iwe,
				    struct ralink_scan_data *res, char *custom,
				    char *end)
{
	char *genie, *gpos, *gend;
	u8 *tmp;

	if (iwe->u.data.length == 0)
		return;

	gpos = genie = custom;
	gend = genie + iwe->u.data.length;
	if (gend > end) {
		wpa_printf(MSG_INFO, "IWEVGENIE overflow");
		return;
	}

	tmp = os_realloc(res->ie, res->ie_len + gend - gpos);
	if (tmp == NULL)
		return;
	os_memcpy(tmp + res->ie_len, gpos, gend - gpos);
	res->ie = tmp;
	res->ie_len += gend - gpos;
}

static void wpa_driver_ralink_add_scan_entry(struct wpa_scan_results *res,
					     struct ralink_scan_data *data)
{
	struct wpa_scan_res **tmp;
	struct wpa_scan_res *r;
	size_t extra_len;
	u8 *pos, *end, *ssid_ie = NULL, *rate_ie = NULL;

	/* Figure out whether we need to fake any IEs */
	pos = data->ie;
	end = pos + data->ie_len;
	while (pos && pos + 1 < end) {
		if (pos + 2 + pos[1] > end)
			break;
		if (pos[0] == WLAN_EID_SSID)
			ssid_ie = pos;
		else if (pos[0] == WLAN_EID_SUPP_RATES)
			rate_ie = pos;
		else if (pos[0] == WLAN_EID_EXT_SUPP_RATES)
			rate_ie = pos;
		pos += 2 + pos[1];
	}

	extra_len = 0;
	if (ssid_ie == NULL)
		extra_len += 2 + data->ssid_len;
	if (rate_ie == NULL && data->maxrate)
		extra_len += 3;

	r = os_zalloc(sizeof(*r) + extra_len + data->ie_len);
	if (r == NULL)
		return;
	os_memcpy(r, &data->res, sizeof(*r));
	r->ie_len = extra_len + data->ie_len;
	pos = (u8 *) (r + 1);
	if (ssid_ie == NULL) {
		/*
		 * Generate a fake SSID IE since the driver did not report
		 * a full IE list.
		 */
		*pos++ = WLAN_EID_SSID;
		*pos++ = data->ssid_len;
		os_memcpy(pos, data->ssid, data->ssid_len);
		pos += data->ssid_len;
	}
	if (rate_ie == NULL && data->maxrate) {
		/*
		 * Generate a fake Supported Rates IE since the driver did not
		 * report a full IE list.
		 */
		*pos++ = WLAN_EID_SUPP_RATES;
		*pos++ = 1;
		*pos++ = data->maxrate;
	}
	if (data->ie)
		os_memcpy(pos, data->ie, data->ie_len);

	tmp = os_realloc(res->res,
			 (res->num + 1) * sizeof(struct wpa_scan_res *));
	if (tmp == NULL) {
		os_free(r);
		return;
	}
	tmp[res->num++] = r;
	res->res = tmp;
}

static int ralink_19_iw_point(struct wpa_driver_ralink_data *drv, u16 cmd)
{
	return drv->we_version_compiled > 18 &&
		(cmd == SIOCGIWESSID || cmd == SIOCGIWENCODE ||
		 cmd == IWEVGENIE || cmd == IWEVCUSTOM);
}

/**
 * wpa_driver_ralink_get_scan_results - Fetch the latest scan results
 * @priv: Pointer to private ralink data from wpa_driver_ralink_init()
 * Returns: Scan results on success, -1 on failure
 */
static struct wpa_scan_results * wpa_driver_ralink_get_scan_results2(void *priv)
{
	struct wpa_driver_ralink_data *drv = priv;
	size_t ap_num = 0, len;
	int first;
	u8 *res_buf;
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom;
	struct wpa_scan_results *res;
	struct ralink_scan_data data;

	res_buf = wpa_driver_ralink_giwscan(drv, &len);
	if (res_buf == NULL) {
		return NULL;
	}
	ap_num = 0;
	first = 1;
	res = os_zalloc(sizeof(*res));
	if (res == NULL) {
		os_free(res_buf);
		return NULL;
	}
	pos = (char *) res_buf;
	end = (char *) res_buf + len;
	os_memset(&data, 0, sizeof(data));

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		if (iwe->len <= IW_EV_LCP_LEN)
			break;

		custom = pos + IW_EV_POINT_LEN;
		if (ralink_19_iw_point(drv, iwe->cmd)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			os_memcpy(dpos, pos + IW_EV_LCP_LEN,
				  sizeof(struct iw_event) - dlen);
		} else {
			os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}
		switch (iwe->cmd) {
		case SIOCGIWAP:
			if (!first)
				wpa_driver_ralink_add_scan_entry(res, &data);
			first = 0;
			os_free(data.ie);
			os_memset(&data, 0, sizeof(data));
			os_memcpy(data.res.bssid,
				  iwe->u.ap_addr.sa_data, ETH_ALEN);
			break;
		case SIOCGIWMODE:
			ralink_get_scan_mode(iwe, &data);
			break;
		case SIOCGIWESSID:
			ralink_get_scan_ssid(iwe, &data, custom, end);
			break;
		case SIOCGIWFREQ:
			ralink_get_scan_freq(iwe, &data);
			break;
		case IWEVQUAL:
			ralink_get_scan_qual(iwe, &data);
			break;
		case SIOCGIWENCODE:
			ralink_get_scan_encode(iwe, &data);
			break;
		case IWEVGENIE:
			ralink_get_scan_iwevgenie(iwe, &data, custom, end);
			break;
		}
		pos += iwe->len;
	}
	os_free(res_buf);
	res_buf = NULL;
	if (!first) {
		wpa_driver_ralink_add_scan_entry(res, &data);
	}
	os_free(data.ie);
	return res;
}

static int ralink_set_auth_mode(struct wpa_driver_ralink_data *drv,
				NDIS_802_11_AUTHENTICATION_MODE mode)
{
	NDIS_802_11_AUTHENTICATION_MODE auth_mode = mode;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (ralink_set_oid(drv, OID_802_11_AUTHENTICATION_MODE,
			   (char *) &auth_mode, sizeof(auth_mode)) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "OID_802_11_AUTHENTICATION_MODE (%d)",
			   (int) auth_mode);
		return -1;
	}
	return 0;
}

static int ralink_set_encr_type(struct wpa_driver_ralink_data *drv,
				NDIS_802_11_WEP_STATUS encr_type)
{
	NDIS_802_11_WEP_STATUS wep_status = encr_type;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (ralink_set_oid(drv, OID_802_11_WEP_STATUS,
			   (char *) &wep_status, sizeof(wep_status)) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "OID_802_11_WEP_STATUS (%d)",
			   (int) wep_status);
		return -1;
	}
	return 0;
}


static int wpa_driver_ralink_remove_key(struct wpa_driver_ralink_data *drv,
					int key_idx, const u8 *addr,
					const u8 *bssid, int pairwise)
{
	NDIS_802_11_REMOVE_KEY rkey;
	NDIS_802_11_KEY_INDEX _index;
	int res, res2;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	os_memset(&rkey, 0, sizeof(rkey));

	rkey.Length = sizeof(rkey);
	rkey.KeyIndex = key_idx;

	if (pairwise)
		rkey.KeyIndex |= 1 << 30;

	os_memcpy(rkey.BSSID, bssid, ETH_ALEN);

	res = ralink_set_oid(drv, OID_802_11_REMOVE_KEY, (char *) &rkey,
			     sizeof(rkey));

	/* AlbertY@20060210 removed it */
	if (0 /* !pairwise */) {
		res2 = ralink_set_oid(drv, OID_802_11_REMOVE_WEP,
				      (char *) &_index, sizeof(_index));
	} else
		res2 = 0;

	if (res < 0 && res2 < 0)
		return res;
	return 0;
}

static int wpa_driver_ralink_add_wep(struct wpa_driver_ralink_data *drv,
				     int pairwise, int key_idx, int set_tx,
				     const u8 *key, size_t key_len)
{
	NDIS_802_11_WEP *wep;
	size_t len;
	int res;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	len = 12 + key_len;
	wep = os_zalloc(len);
	if (wep == NULL)
		return -1;

	wep->Length = len;
	wep->KeyIndex = key_idx;

	if (set_tx)
		wep->KeyIndex |= 0x80000000;

	wep->KeyLength = key_len;
	os_memcpy(wep->KeyMaterial, key, key_len);

	wpa_hexdump_key(MSG_MSGDUMP, "RALINK: OID_802_11_ADD_WEP",
			(const u8 *) wep, len);
	res = ralink_set_oid(drv, OID_802_11_ADD_WEP, (char *) wep, len);

	os_free(wep);

	return res;
}

static int wpa_driver_ralink_set_key(void *priv, wpa_alg alg, const u8 *addr,
				     int key_idx, int set_tx,
				     const u8 *seq, size_t seq_len,
				     const u8 *key, size_t key_len)
{
	struct wpa_driver_ralink_data *drv = priv;
	size_t len, i;
	NDIS_802_11_KEY *nkey;
	int res, pairwise;
	u8 bssid[ETH_ALEN];

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	bAddWepKey = FALSE;

	if (addr == NULL || os_memcmp(addr, "\xff\xff\xff\xff\xff\xff",
				      ETH_ALEN) == 0) {
		/* Group Key */
		pairwise = 0;
		wpa_driver_ralink_get_bssid(drv, bssid);
	} else {
		/* Pairwise Key */
		pairwise = 1;
		os_memcpy(bssid, addr, ETH_ALEN);
	}

	if (alg == WPA_ALG_NONE || key_len == 0) {
		return wpa_driver_ralink_remove_key(drv, key_idx, addr, bssid,
						    pairwise);
	}

	if (alg == WPA_ALG_WEP) {
		bAddWepKey = TRUE;
		return wpa_driver_ralink_add_wep(drv, pairwise, key_idx,
						 set_tx, key, key_len);
	}

	len = 12 + 6 + 6 + 8 + key_len;

	nkey = os_zalloc(len);
	if (nkey == NULL)
		return -1;

	nkey->Length = len;
	nkey->KeyIndex = key_idx;

	if (set_tx)
		nkey->KeyIndex |= 1 << 31;

	if (pairwise)
		nkey->KeyIndex |= 1 << 30;

	if (seq && seq_len)
		nkey->KeyIndex |= 1 << 29;

	nkey->KeyLength = key_len;
	os_memcpy(nkey->BSSID, bssid, ETH_ALEN);

	if (seq && seq_len) {
		for (i = 0; i < seq_len; i++)
			nkey->KeyRSC |= seq[i] << (i * 8);
	}
	if (alg == WPA_ALG_TKIP && key_len == 32) {
		os_memcpy(nkey->KeyMaterial, key, 16);
		os_memcpy(nkey->KeyMaterial + 16, key + 24, 8);
		os_memcpy(nkey->KeyMaterial + 24, key + 16, 8);
	} else {
		os_memcpy(nkey->KeyMaterial, key, key_len);
	}

	wpa_printf(MSG_DEBUG, "%s: alg=%d key_idx=%d set_tx=%d seq_len=%lu "
		   "key_len=%lu", __FUNCTION__, alg, key_idx, set_tx,
		   (unsigned long) seq_len, (unsigned long) key_len);

	wpa_hexdump_key(MSG_MSGDUMP, "RALINK: OID_802_11_ADD_KEY",
			(const u8 *) nkey, len);
	res = ralink_set_oid(drv, OID_802_11_ADD_KEY, (char *) nkey, len);
	os_free(nkey);

	return res;
}

static int wpa_driver_ralink_disassociate(void *priv, const u8 *addr,
					int reason_code)
{
	struct wpa_driver_ralink_data *drv = priv;

	if (drv->g_driver_down == 1)
		return -1;
	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	if (ralink_set_oid(drv, OID_802_11_DISASSOCIATE, "    ", 4) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "OID_802_11_DISASSOCIATE");
	}

	return 0;
}

static int wpa_driver_ralink_deauthenticate(void *priv, const u8 *addr,
					  int reason_code)
{
	struct wpa_driver_ralink_data *drv = priv;

	wpa_printf(MSG_DEBUG, "g_driver_down = %d", drv->g_driver_down);

	if (drv->g_driver_down == 1)
		return -1;

	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	if (ralink_get_new_driver_flag(drv) == 0) {
		return wpa_driver_ralink_disassociate(priv, addr, reason_code);
	} else {
		MLME_DEAUTH_REQ_STRUCT mlme;
		os_memset(&mlme, 0, sizeof(MLME_DEAUTH_REQ_STRUCT));
		mlme.Reason = reason_code;
		os_memcpy(mlme.Addr, addr, MAC_ADDR_LEN);
		return ralink_set_oid(drv, OID_802_11_DEAUTHENTICATION,
				      (char *) &mlme,
				      sizeof(MLME_DEAUTH_REQ_STRUCT));
	}
}

static int wpa_driver_ralink_set_gen_ie(void *priv, const u8 *ie, size_t ie_len)
{
	struct wpa_driver_ralink_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) ie;
	iwr.u.data.length = ie_len;

	wpa_hexdump(MSG_DEBUG, "wpa_driver_ralink_set_gen_ie: ",
			    (u8 *) ie, ie_len);

	if (ioctl(drv->ioctl_sock, SIOCSIWGENIE, &iwr) < 0) {
		perror("ioctl[SIOCSIWGENIE]");
		ret = -1;
	}

	return ret;
}

static int
wpa_driver_ralink_associate(void *priv,
			    struct wpa_driver_associate_params *params)
{
	struct wpa_driver_ralink_data *drv = priv;

	NDIS_802_11_NETWORK_INFRASTRUCTURE mode;
	NDIS_802_11_AUTHENTICATION_MODE auth_mode;
	NDIS_802_11_WEP_STATUS encr;
	BOOLEAN		ieee8021xMode;
	BOOLEAN 	ieee8021x_required_key = TRUE;

	if (drv->g_driver_down == 1)
		return -1;
	
	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

	if (params->mode == IEEE80211_MODE_IBSS)
		mode = Ndis802_11IBSS;
	else
		mode = Ndis802_11Infrastructure;

	if (ralink_set_oid(drv, OID_802_11_INFRASTRUCTURE_MODE,
			 (char *) &mode, sizeof(mode)) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "OID_802_11_INFRASTRUCTURE_MODE (%d)",
			   (int) mode);
		/* Try to continue anyway */
	}

#ifdef CONFIG_WPS
	if (params->key_mgmt_suite == KEY_MGMT_WPS) {
		UCHAR enable_wps = 0x80;
		/* trigger driver support wpa_supplicant */
		if (ralink_set_oid(drv, RT_OID_WPA_SUPPLICANT_SUPPORT,
				   (PCHAR) &enable_wps, sizeof(UCHAR)) < 0)
		{
			wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "RT_OID_WPA_SUPPLICANT_SUPPORT (%d)",
			   (int) enable_wps);
		}

		wpa_driver_ralink_set_gen_ie(priv, params->wpa_ie, params->wpa_ie_len);

		ralink_set_auth_mode(drv, Ndis802_11AuthModeOpen);

		ralink_set_encr_type(drv, Ndis802_11EncryptionDisabled);
	} else
#endif /* CONFIG_WPS */
	{
#ifdef CONFIG_WPS
		UCHAR enable_wpa_supplicant = 0x00;

		if (drv->ap_scan == 1)
			enable_wpa_supplicant = 0x01;
		else
			enable_wpa_supplicant = 0x02;
				
		/* trigger driver support wpa_supplicant */
		if (ralink_set_oid(drv, RT_OID_WPA_SUPPLICANT_SUPPORT,
				   (PCHAR) &enable_wpa_supplicant, sizeof(UCHAR)) < 0)
		{
			wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "RT_OID_WPA_SUPPLICANT_SUPPORT (%d)",
			   (int) enable_wpa_supplicant);
		}

		wpa_driver_ralink_set_gen_ie(priv, "", 0);
#endif /* CONFIG_WPS */
	if (params->wpa_ie == NULL || params->wpa_ie_len == 0) {
		if (params->auth_alg & AUTH_ALG_SHARED_KEY) {
			if (params->auth_alg & AUTH_ALG_OPEN_SYSTEM)
				auth_mode = Ndis802_11AuthModeAutoSwitch;
			else
				auth_mode = Ndis802_11AuthModeShared;
		} else
			auth_mode = Ndis802_11AuthModeOpen;
	} else if (params->wpa_ie[0] == WLAN_EID_RSN) {
		if (params->key_mgmt_suite == KEY_MGMT_PSK)
			auth_mode = Ndis802_11AuthModeWPA2PSK;
		else
			auth_mode = Ndis802_11AuthModeWPA2;
	} else {
		if (params->key_mgmt_suite == KEY_MGMT_WPA_NONE)
			auth_mode = Ndis802_11AuthModeWPANone;
		else if (params->key_mgmt_suite == KEY_MGMT_PSK)
			auth_mode = Ndis802_11AuthModeWPAPSK;
		else
			auth_mode = Ndis802_11AuthModeWPA;
	}

	switch (params->pairwise_suite) {
	case CIPHER_CCMP:
		encr = Ndis802_11Encryption3Enabled;
		break;
	case CIPHER_TKIP:
		encr = Ndis802_11Encryption2Enabled;
		break;
	case CIPHER_WEP40:
	case CIPHER_WEP104:
		encr = Ndis802_11Encryption1Enabled;
		break;
	case CIPHER_NONE:
		if (params->group_suite == CIPHER_CCMP)
			encr = Ndis802_11Encryption3Enabled;
		else if (params->group_suite == CIPHER_TKIP)
			encr = Ndis802_11Encryption2Enabled;
		else
			encr = Ndis802_11EncryptionDisabled;
		break;
	default:
		encr = Ndis802_11EncryptionDisabled;
		break;
	}

	ralink_set_auth_mode(drv, auth_mode);

	/* notify driver that IEEE8021x mode is enabled */
	if (params->key_mgmt_suite == KEY_MGMT_802_1X_NO_WPA)
		{			
			ieee8021xMode = TRUE;
			if (bAddWepKey) 
				ieee8021x_required_key = FALSE;
		}
	else
		ieee8021xMode = FALSE;

		if (ralink_set_oid(drv, OID_802_11_SET_IEEE8021X_REQUIRE_KEY, (char *) &ieee8021x_required_key, sizeof(BOOLEAN)) < 0)
		{
			wpa_printf(MSG_DEBUG, "ERROR: Failed to set OID_802_11_SET_IEEE8021X_REQUIRE_KEY(%d)", (int) ieee8021x_required_key);
		}
		else
		{
			wpa_printf(MSG_DEBUG, "ieee8021x_required_key is %s", ieee8021x_required_key ? "TRUE" : "FALSE");
		}
		
	if (ralink_set_oid(drv, OID_802_11_SET_IEEE8021X,
			   (char *) &ieee8021xMode, sizeof(BOOLEAN)) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
			   "OID_802_11_SET_IEEE8021X(%d)",
			   (int) ieee8021xMode);
	}

		ralink_set_encr_type(drv, encr);

	if ((ieee8021xMode == FALSE) &&
	    (encr == Ndis802_11Encryption1Enabled)) {
		/* static WEP */
		int enabled = 0;
		if (ralink_set_oid(drv, OID_802_11_DROP_UNENCRYPTED,
				   (char *) &enabled, sizeof(enabled)) < 0) {
			wpa_printf(MSG_DEBUG, "RALINK: Failed to set "
				   "OID_802_11_DROP_UNENCRYPTED(%d)",
				   (int) encr);
			}
		}
	}

	return wpa_driver_ralink_set_ssid(drv, params->ssid, params->ssid_len);
}

static int wpa_driver_ralink_set_probe_req_ie(void *priv, const u8 *ies, size_t ies_len)
{
	struct wpa_driver_ralink_data *drv = priv;
	
	wpa_hexdump(MSG_DEBUG, "wpa_driver_ralink_set_probe_req_ie: ",
			    (u8 *) ies, ies_len);

	if (ralink_set_oid(drv, RT_OID_WPS_PROBE_REQ_IE,
			   (char *) ies, ies_len) < 0) {
		wpa_printf(MSG_DEBUG, "RALINK: Failed to set RT_OID_WPS_PROBE_REQ_IE");
	}
}

static int
wpa_driver_ralink_set_countermeasures(void *priv, int enabled)
{
	struct wpa_driver_ralink_data *drv = priv;
	if (drv->g_driver_down == 1)
		return -1;
	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
	return ralink_set_oid(drv, OID_SET_COUNTERMEASURES, (char *) &enabled,
			      sizeof(int));
}

const struct wpa_driver_ops wpa_driver_ralink_ops = {
	.name = "ralink",
	.desc = "Ralink Wireless Client driver",
	.get_bssid = wpa_driver_ralink_get_bssid,
	.get_ssid = wpa_driver_ralink_get_ssid,
	.set_key = wpa_driver_ralink_set_key,
	.init = wpa_driver_ralink_init,
	.deinit = wpa_driver_ralink_deinit,
	.set_countermeasures	= wpa_driver_ralink_set_countermeasures,
	.scan = wpa_driver_ralink_scan,
	.get_scan_results2 = wpa_driver_ralink_get_scan_results2,
	.deauthenticate = wpa_driver_ralink_deauthenticate,
	.disassociate = wpa_driver_ralink_disassociate,
	.associate = wpa_driver_ralink_associate,
	.add_pmkid = wpa_driver_ralink_add_pmkid,
	.remove_pmkid = wpa_driver_ralink_remove_pmkid,
	.flush_pmkid = wpa_driver_ralink_flush_pmkid,
	.set_probe_req_ie = wpa_driver_ralink_set_probe_req_ie,
};
