/*
 *   Copyright (C) 2009-2014 by Jonathan Naylor G4KLX
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

#ifndef	RepeaterProtocolHander_H
#define	RepeaterProtocolHander_H

#include <wx/wx.h>
#include <wx/socket.h>

#include "DStarDefines.h"
#include "HeaderData.h"

class CRepeaterProtocolHandler {
public:
	CRepeaterProtocolHandler(const wxIPV4address& localAddress,
				 const wxIPV4address& gatewayAddress,
	 			 const wxString& name);
	~CRepeaterProtocolHandler();

	bool write(const CHeaderData& header, bool busy=false);
	bool write(const void* data, unsigned int length,
		unsigned int errors, bool end, bool busy=false);
	bool writePoll(const wxString& text);
	bool writeRegister();

	bool isLocal();

	NETWORK_TYPE read();
	void         readText(wxString& text, LINK_STATUS& status, wxString& reflector);
	void         readTempText(wxString& text);
	wxString     readStatus1();
	wxString     readStatus2();
	wxString     readStatus3();
	wxString     readStatus4();
	wxString     readStatus5();
	CHeaderData* readHeader();
	unsigned int readData(unsigned char* data, unsigned int length, unsigned char& seqNo);

	void reset();
private:
	wxDatagramSocket m_socket;
	wxIPV4address    m_gatewayAddress;
	wxString         m_name;
	wxUint16         m_outId;
	wxUint8          m_outSeq;
	NETWORK_TYPE     m_type;
	wxUint16         m_inId;
	unsigned char*   m_buffer;
	unsigned int     m_length;

	bool readPackets();
};

#endif
