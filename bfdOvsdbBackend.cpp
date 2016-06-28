/**************************************************************************
 * Copyright 2016 LinkedIn Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * Author: Ravi Jonnadula
 *
 **************************************************************************/

#include "common.h"
#include "CommandProcessor.h"
#include "utils.h"
#include "bfd.h"
#include "SmartPointer.h"
#include "Beacon.h"
#include "Scheduler.h"
#include "Session.h"
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <stdarg.h>
#include <iostream>
#include <unistd.h>
#include "TimeSpec.h"

#include "SockAddr.h"
#include "bfdOvsdbBackend.h"
#include "bfdOvsdbIf.h"

using namespace std;


class OvsCommandProcessor : public CommandProcessor
{

protected:
  Beacon *m_beacon; // never null, never changes
  Scheduler *m_scheduler;

  //
  // These are protected by m_mainLock
  //
  QuickLock m_mainLock;
  pthread_t m_listenThread;
  volatile bool m_isThreadRunning;
  volatile bool m_threadInitComplete; // Set to true after  m_isThreadRunning set true the first time
  volatile bool m_threadStartupSuccess;   //only valid after m_isThreadRunning has been set to true.
  volatile bool m_stopListeningRequested;
  WaitCondition m_threadStartCondition;

public:
  OvsCommandProcessor(Scheduler *scheduler, Beacon *beacon) : CommandProcessor(*beacon),
     m_beacon(beacon),
     m_scheduler(scheduler),
     m_mainLock(true),
     m_isThreadRunning(false),
     m_threadInitComplete(false),
     m_threadStartupSuccess(true),
     m_stopListeningRequested(false)
  {
    /* Initialize Beacon context for OVS interface functions */
    bfd_ovsdb_init_context(beacon);
  }

  virtual ~OvsCommandProcessor()
  {
    StopListening();
    bfd_ovsdb_exit();
  }

  /**
   * See CommandProcessor::BeginListening().
   */
  virtual bool BeginListening(const SockAddr &ATTR_UNUSED(addr));

  /**
   * See CommandProcessor::StopListening().
   */
  virtual void StopListening();

protected:

  static void* doListenThreadCallback(void *arg)
  {
    reinterpret_cast<OvsCommandProcessor *>(arg)->doListenThread();
    return NULL;
  }

  void doListenThread();

  static void handleOvsReadTimerCallback(Timer *timer, void *userdata)
  {
    reinterpret_cast<OvsCommandProcessor *>(userdata)->handleOvsReadTimer(timer);
  }

  void handleOvsReadTimer(Timer *ATTR_UNUSED(timer));

  /**
   *
   * Call only from listen thread.
   * Call with  m_mainLock held.
   *
   * @return bool - false if listening setup failed.
   */
  bool initListening()
  {
    // Do this so low memory will not cause distorted messages
    if (!UtilsInitThread())
    {
      gLog.Message(Log::Error,  "Failed to initialize OVS listen thread. TLS memory failure.");
      return false;
    }

    gLog.Optional(Log::App, "Listening for OVS commands");

    return true;
  }

  /**
   * Checks if a shutdown has been requested. Do not call while holding
   * m_mainLock.
   *
   *
   *
   * @return bool - True if a shutdown was requested.
   */
  bool isStopListeningRequested()
  {
    AutoQuickLock lock(m_mainLock, true);
    return m_stopListeningRequested;
  }

private:
  // Timer
  void deleteTimer(Timer *timer);
  Timer *m_ovsReadTimer;


}; // class OvsCommandProcessor

bool
OvsCommandProcessor::BeginListening(const SockAddr &ATTR_UNUSED(addr))
{
	AutoQuickLock lock(m_mainLock, true);

	pthread_attr_t attr;

	if (m_isThreadRunning)
	{
		LogVerifyFalse("OVS Command Processer already running.");
		return true;
	}

	if (pthread_attr_init(&attr))
		return false;
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);  // we will handle synchronizing

	//m_address = addr;
	m_isThreadRunning = false;
	m_threadInitComplete = false;
	m_threadStartupSuccess = true;
	m_stopListeningRequested = false;

	if (pthread_create(&m_listenThread, NULL, doListenThreadCallback, this))
		return false;

	// Wait for listening, or error.
	while (true)
	{
		lock.LockWait(m_threadStartCondition);

		if (!m_threadInitComplete)
			continue; // spurious signal.

		// We can now allow the worker thread to shutdown if it wants to.
		if (!m_threadStartupSuccess)
		{
			lock.UnLock();
			StopListening();  // Ensure that thread is finished before we return...in case we try again immediately.
			return false;
		}

		break;
	}

	return true;
}

void
OvsCommandProcessor::StopListening()
{
	AutoQuickLock lock(m_mainLock, true);

	if (!m_isThreadRunning)
		return;

	m_stopListeningRequested = true;

	// We need to wait for it to
	while (m_isThreadRunning)
		lock.LockWait(m_threadStartCondition);
}

void
OvsCommandProcessor::doListenThread()
{
	bool initSuccess;
	AutoQuickLock lock(m_mainLock, true);

	gLog.Optional(Log::AppDetail, "OVS Listen Thread Started");

	initSuccess = initListening();
	m_threadStartupSuccess = initSuccess;
	m_isThreadRunning = true;
	m_threadInitComplete = true;

	// Signal setup completed (success, or failure).
	lock.SignalAndUnlock(m_threadStartCondition);

	// do Stuff
	if (initSuccess)
	{
		char name[32] = "<BFD-Ovs-Commands>";
		m_ovsReadTimer = m_scheduler->MakeTimer(name);
		m_ovsReadTimer->SetCallback(handleOvsReadTimerCallback,  this);
		m_ovsReadTimer->SetPriority(Timer::Priority::Low);
		m_ovsReadTimer->SetMicroTimer(1000000);
	}

	lock.Lock();
	m_isThreadRunning = false;
	lock.SignalAndUnlock(m_threadStartCondition);
	gLog.Optional(Log::AppDetail, "OVS Listen Thread Shutdown");

	return;
}

void
OvsCommandProcessor::handleOvsReadTimer(Timer *ATTR_UNUSED(timer))
{
	if (isStopListeningRequested())
		return;

	/* hook with OVS IF calls */
	bfd_ovsdb_init_poll_loop();

	/* Restart the timer */
	m_ovsReadTimer->UpdateMicroTimer(1000000);
}

void
OvsCommandProcessor::deleteTimer(Timer *timer)
{
	LogAssert(m_scheduler->IsMainThread());
	if (m_scheduler && timer)
	{
		gLog.Message(Log::Temp,  "Free timer %p", timer);
		m_scheduler->FreeTimer(timer);
	}
}


CommandProcessor* MakeOvsCommandProcessor(Scheduler *scheduler, Beacon *beacon)
{
  return new OvsCommandProcessor(scheduler, beacon);
}

bool
bfdBackendSetGlobals(void *bea, bfdOvsdbIfGlobal_t *bfd_if_global)
{
	Beacon *beacon = reinterpret_cast<Beacon *>(bea);

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MIN_RX_INTERVAL)) {
		gLog.Message(Log::Debug,  "Setting Min_Rx to %d",  bfd_if_global->minRxInterval);
		beacon->SetDefMinTxInterval(bfd_if_global->minRxInterval);
	}

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MIN_TX_INTERVAL)) {
		gLog.Message(Log::Debug,  "Setting Min_Tx to %d",  bfd_if_global->minTxInterval);
		beacon->SetDefMinTxInterval(bfd_if_global->minTxInterval);
	}

	if (IS_VALID(bfd_if_global->valid, BFD_OVSDB_IF_GLOBAL_MULTIPLIER)) {
		gLog.Message(Log::Debug,  "Setting Multiplier to %d",  bfd_if_global->multiplier);
		beacon->SetDefMulti(uint8_t(bfd_if_global->multiplier));
	}

	return true;
}

bool
bfdBackendHandleSession(void *bea, bfdOvsdbIfSession_t *bfd_if_session)
{
	Beacon *beacon = reinterpret_cast<Beacon *>(bea);
	Session *session = NULL;
	IpAddr remote;
	IpAddr local;

	if (!remote.FromString(bfd_if_session->remote_address)) {
		return false;
	}
	if (!local.FromString(bfd_if_session->local_address)) {
		return false;
	}

	if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_ADD) {
		if(beacon->StartActiveSession(remote, local)) {
			gLog.Message(Log::Debug,  "New session created for remote=%s local=%s", remote.ToString(), local.ToString());
			// Set session defaults to the DB
			return bfdBackendUpdateSessionDefaults(bfd_if_session->remote_address, bfd_if_session->local_address);
		}
	} else if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_MODIFY) {
		if(beacon->StartActiveSession(remote, local)) {
			gLog.Message(Log::Debug,  "New session created for remote=%s local=%s", remote.ToString(), local.ToString());
			// Set session defaults to the DB
			return bfdBackendUpdateSessionDefaults(bfd_if_session->remote_address, bfd_if_session->local_address);
		}
	} else if (bfd_if_session->action == BFD_OVSDB_IF_SESSION_ACTION_DEL) {
		session = beacon->FindSessionIp(remote, local);
		if ( !session ) {
			return false;
		}

		beacon->KillSession(session);
		session = NULL; // Session is now invalid
		return true;
	}

	return false;
}

bool
bfdBackendUpdateSessionDefaults(char *remote, char *local)
{
	bfdOvsdbIfSession_t bfd_if_session;

	memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));
	bfd_if_session.remote_address = remote;
	bfd_if_session.local_address = local;

	bfd_if_session.local_state = BFD_OVSDB_IF_SESSION_STATE_DOWN;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE);

	bfd_if_session.remote_state = BFD_OVSDB_IF_SESSION_STATE_DOWN;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE);

	if (!bfdOvsdbIfUpdateSession(&bfd_if_session)) {
		gLog.Message(Log::Error,  "Failed to Update Session default state to OVS.");
		return false;
	}

	return true;
}

bool
bfdBackendUpdateSessionChange(Session *session)
{
	bfdOvsdbIfSession_t bfd_if_session;
	Session::ExtendedStateInfo exInfo;

	memset(&bfd_if_session, 0, sizeof(bfdOvsdbIfSession_t));
	bfd_if_session.sessionId = session->GetId();
	bfd_if_session.remote_address = const_cast<char *>(session->GetRemoteAddress().ToString());
	bfd_if_session.local_address = const_cast<char *>(session->GetLocalAddress().ToString());

	bfd_if_session.local_state = session->GetState();
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_STATE);
	bfd_if_session.remote_state = session->GetRemoteState();
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_STATE);

	session->GetExtendedState(exInfo);
	bfd_if_session.remote_diag = exInfo.remoteDiag;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_DIAG);
	bfd_if_session.local_diag = exInfo.localDiag;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_LOCAL_DIAG);

	bfd_if_session.remoteMultiplier = exInfo.remoteDetectMult;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MULTI);

	bfd_if_session.remoteMinTxInterval = exInfo.remoteDesiredMinTxInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_TX);

	bfd_if_session.remoteMinRxInterval = exInfo.remoteMinRxInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_REMOTE_MIN_RX);

	bfd_if_session.transmitInterval = exInfo.transmitInterval;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_TRANSMIT_INTERVAL);
	bfd_if_session.detectionTime = exInfo.detectionTime;
	SET_VALID(bfd_if_session.valid, BFD_OVSDB_IF_SESSION_VALID_DETECTION_TIME);

	if (!bfdOvsdbIfUpdateSession(&bfd_if_session)) {
		gLog.Message(Log::Error,  "Failed to Update Session Change to OVS.");
		return false;
	}

	gLog.Message(Log::Debug, "DB variable state before update: State=%d, Remote_state=%d Diag=%d Remote_diag=%d\n",
			session->GetDbState(), session->GetDbRemoteState(),
			session->GetDbLocalDiag(), session->GetDbRemoteDiag());

	session->SetDbState(session->GetState());
	session->SetDbRemoteState(session->GetRemoteState());
	session->SetDbLocalDiag(exInfo.localDiag);
	session->SetDbRemoteDiag(exInfo.remoteDiag);

	gLog.Message(Log::Debug, "DB variable state after update: State=%d, Remote_state=%d Diag=%d Remote_diag=%d\n",
			session->GetDbState(), session->GetDbRemoteState(),
			session->GetDbLocalDiag(), session->GetDbRemoteDiag());

	return true;
}
