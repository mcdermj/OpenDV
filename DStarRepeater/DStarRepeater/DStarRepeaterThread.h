/*
 *   Copyright (C) 2011-2015 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef	DStarRepeaterThread_H
#define	DStarRepeaterThread_H

#include "DStarRepeaterStatusData.h"
#include "RepeaterProtocolHandler.h"
#include "ExternalController.h"
#include "DStarRepeaterDefs.h"
#include "CallsignList.h"
#include "Modem.h"

#include <wx/wx.h>

enum FRAME_TYPE {
	FRAME_NORMAL,
	FRAME_SYNC,
	FRAME_END
};

class IDStarRepeaterThread : public wxThread {
public:
	IDStarRepeaterThread();

	virtual ~IDStarRepeaterThread() = 0;

	virtual void setCallsign(const wxString& callsign, const wxString& gateway, DSTAR_MODE mode, ACK_TYPE ack, bool restriction, bool rpt1Validation, bool dtmfBlanking, bool errorReply) = 0;

	void setProtocolHandler(CRepeaterProtocolHandler* handler);
	void setModem(CModem* modem);

	virtual void setController(CExternalController* controller, unsigned int activeHangTime) = 0;

	virtual void setTimes(unsigned int timeout, unsigned int ackTime) = 0;

	virtual void setBeacon(unsigned int time, const wxString& text, bool voice, TEXT_LANG language) = 0;
	virtual void setAnnouncement(bool enabled, unsigned int time, const wxString& recordRPT1, const wxString& recordRPT2, const wxString& deleteRPT1, const wxString& deleteRPT2) = 0;
	virtual void setControl(bool enabled, const wxString& rpt1Callsign,
		const wxString& rpt2Callsign, const wxString& shutdown,
		const wxString& startup, const wxArrayString &command,
		const wxArrayString& status, const wxArrayString& outputs
	) { };
	virtual void setOutputs(bool out1, bool out2, bool out3, bool out4) = 0;
	virtual void setLogging(bool logging, const wxString& dir) = 0;

	virtual void setWhiteList(CCallsignList* list) = 0;
	virtual void setBlackList(CCallsignList* list) = 0;
	virtual void setGreyList(CCallsignList* list) = 0;

	virtual void shutdown() = 0;
	virtual void startup() = 0;

	virtual CDStarRepeaterStatusData* getStatus() = 0;

protected:
	CModem *m_modem;
	CRepeaterProtocolHandler*  m_protocolHandler;

private:
};

#endif
