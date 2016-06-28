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
 **************************************************************************/

#pragma once

// Class for handling command communication with the OVSDB
class Beacon;
class Scheduler;

/**
 * Interface factory. Use delete to free this.
 *
 * Requires UtilsInit() to have been called.
 *
 * @throw - May throw an exception.
 *
 * @return CommandProcessor* - Will not return NULL.
 */
class CommandProcessor* MakeOvsCommandProcessor(Scheduler *scheduler, Beacon *beacon);

bool bfdBackendUpdateSessionDefaults(char *remote, char *local);
bool bfdBackendUpdateSessionChange(Session *session);