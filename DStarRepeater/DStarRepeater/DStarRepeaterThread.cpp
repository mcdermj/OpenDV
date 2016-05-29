/*
 *	Copyright (C) 2013 by Jonathan Naylor, G4KLX
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; version 2 of the License.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 */

#include "DStarRepeaterThread.h"

IDStarRepeaterThread::IDStarRepeaterThread():
wxThread(wxTHREAD_JOINABLE)
{
}

IDStarRepeaterThread::~IDStarRepeaterThread()
{
}

void IDStarRepeaterThread::setModem(CModem* modem)
{
	wxASSERT(modem != NULL);

	m_modem = modem;
}

void IDStarRepeaterThread::setProtocolHandler(CRepeaterProtocolHandler* handler, bool local)
{
	wxASSERT(handler != NULL);

	m_protocolHandler = handler;
}
