#pragma once

template<class StateStore>
class KeyCloakClient {
public:
    StateStore state_store;
};

KeyCloakClient<MemoryStateStore> mkc;