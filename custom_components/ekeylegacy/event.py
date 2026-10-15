"""Event entity for Ekey (legacy) integration."""

import asyncio
import logging
import struct

from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PORT, CONF_TYPE
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import CONF_DELIMITER, DOMAIN

_LOGGER = logging.getLogger(__name__)

class EkeyLegacyAuthEvent(EventEntity):
    """Representation of a Ekey (legacy) event entity."""

    _attr_device_class = EventDeviceClass.BUTTON
    _attr_event_types = ["authenticated", "failed"]

    def __init__(self, port: int, type: str, delimiter: str) -> None:
        """Initialize the Ekey (legacy) event entity."""
        self._attr_name = f"ekey {type}"
        self._attr_unique_id = f"{type}-{port}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{type}-{port}")},
            manufacturer="ekey",
        )

        self._conf_port = port
        self._conf_type = type
        self._conf_delimiter = delimiter
        self._transport = None

    async def async_added_to_hass(self) -> None:
        """Register callbacks."""
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _EkeyUDPProtocol(self.hass, self),
            local_addr=("0.0.0.0", self._conf_port),
        )

    @callback
    def async_handle_event(self, data: bytes) -> None:
        """Handle the Ekey (legacy) event."""
        is_successful = False
        event_data = {}

        # Handle binary rare protocols
        if self._conf_type in ("rare", "rare v2"):
            try:
                # rare/rare v2 binary format parsing based on documentation
                # Version (4 bytes uint32), followed by ActionCode/EventID, TerminalID, Serial, Relay, Reserved, UserID, FingerID, Event, Time, Name, PersonalNum
                if len(data) < 4:
                    return
                version = struct.unpack_from("<I", data, 0)[0]
                
                if self._conf_type == "rare" and version == 3:
                    # Format rare (Table 110)[cite: 1]
                    # <I (version), I (action_code), I (terminal_id), 14s (serial), B (relay), B (reserved), I (user_id), I (finger_id), 16s (event), 16s (time)
                    unpacked = struct.unpack_from("<III 14s BB II 16s 16s", data, 0)
                    event_data = {
                        "version": unpacked[0],
                        "action": str(unpacked[1]),
                        "terminal_id": hex(unpacked[2]),
                        "scanner": unpacked[3].decode("ascii", errors="ignore").strip(),
                        "relay": unpacked[4],
                        "user": str(unpacked[6]).lstrip("0"),
                        "finger": str(unpacked[7]),
                        "event": unpacked[8].decode("ascii", errors="ignore").strip(),
                        "time": unpacked[9].decode("ascii", errors="ignore").strip(),
                    }
                    if event_data["action"] == "1":
                        is_successful = True

                elif self._conf_type == "rare v2" and version == 5:
                    # Format rare v2 (Table 111)[cite: 2, 3]
                    unpacked = struct.unpack_from("<III 14s BB II 16s 16s", data, 0)
                    event_data = {
                        "version": unpacked[0],
                        "event_id": str(unpacked[1]),
                        "terminal_id": hex(unpacked[2]),
                        "scanner": unpacked[3].decode("ascii", errors="ignore").strip(),
                        "relay": unpacked[4],
                        "user": str(unpacked[6]).lstrip("0"),
                        "finger": str(unpacked[7]),
                        "event": unpacked[8].decode("ascii", errors="ignore").strip(),
                        "time": unpacked[9].decode("ascii", errors="ignore").strip(),
                    }
                    # Bei rare v2 wird die Authentifizierung meist über Ereignisse definiert; 
                    # standardmäßig werten wir es aus, wenn Relais aktiv ist oder Action/Event vorliegt.
                    if unpacked[4] > 0:
                        is_successful = True
                else:
                    return
            except Exception as ex:
                _LOGGER.error("Failed to parse binary rare packet: %s", ex)
                return

        else:
            # Handle text-based protocols (home, multi, net, net v2)
            message = data.decode("ascii", errors="ignore")
            parts = message.strip().split(self._conf_delimiter)

            _LOGGER.info(
                "Received event '%s'",
                message,
            )

            if self._conf_type == "home" and len(parts) == 6:
                event_data = {
                    "type": parts[0],
                    "user": parts[1].lstrip("0"),
                    "finger": parts[2],
                    "scanner": parts[3],
                    "action": parts[4],
                    "relay": parts[5],
                }
                if event_data["action"] == "1":
                    is_successful = True

            elif self._conf_type == "multi" and len(parts) == 10:
                event_data = {
                    "type": parts[0],
                    "user": parts[1].lstrip("0"),
                    "user_name": parts[2].lstrip("-"),
                    "user_status": parts[3],
                    "finger": parts[4],
                    "key": parts[5],
                    "scanner": parts[6],
                    "scanner_name": parts[7].lstrip("-"),
                    "action": parts[8],
                    "digital_input": parts[9],
                }
                if event_data["action"] == "1":
                    is_successful = True

            elif self._conf_type == "net" and len(parts) >= 5:
                # Protokollformat net (Table 112)[cite: 4]: Pakettyp, BenutzerID, FingerID, Seriennummer, AktionsCode
                event_data = {
                    "packet_type": parts[0],
                    "user": parts[1].lstrip("0"),
                    "finger": parts[2],
                    "scanner": parts[3],
                    "action": parts[4],
                }
                if event_data.get("action") == "000001":
                    is_successful = True

            elif self._conf_type == "net v2" and len(parts) >= 5:
                # Protokollformat net v2 (Table 113)[cite: 4, 5]: Pakettyp, BenutzerID, ID, Seriennummer, Ereignis
                event_data = {
                    "packet_type": parts[0],
                    "user": parts[1].lstrip("0"),
                    "finger": parts[2],
                    "scanner": parts[3],
                    "event": parts[4],
                }
                # Net v2 sendet Ereignis-IDs (z.B. erfolgreicher Zutritt)
                if event_data.get("event") != "000000":
                    is_successful = True

            else:
                return

        if is_successful:
            self._trigger_event("authenticated", event_data)
        else:
            self._trigger_event("failed", event_data)

        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        """Unregister the Ekey (legacy) event."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None


class _EkeyUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for incoming Ekey packets."""

    def __init__(self, hass: HomeAssistant, entity: EkeyLegacyAuthEvent) -> None:
        self.hass = hass
        self.entity = entity

    def datagram_received(self, data: bytes, addr) -> None:
        self.entity.async_handle_event(data)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the Ekey (legacy) event platform."""
    async_add_entities(
        [
            EkeyLegacyAuthEvent(
                config_entry.data[CONF_PORT],
                config_entry.data[CONF_TYPE],
                config_entry.data[CONF_DELIMITER],
            )
        ]
    )
