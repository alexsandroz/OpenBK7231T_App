#ifndef __CMD_PUBLIC_H__
#define __CMD_PUBLIC_H__

#include "../new_common.h"

typedef enum commandResult_e {
	CMD_RES_OK,
	CMD_RES_UNKNOWN_COMMAND,
	CMD_RES_NOT_ENOUGH_ARGUMENTS,
	CMD_RES_EMPTY_STRING,
	CMD_RES_BAD_ARGUMENT,
	CMD_RES_ERROR,

} commandResult_t;

typedef commandResult_t (*commandHandler_t)(const void* context, const char* cmd, const char* args, int flags);

// command was entered in console (web app etc)
#define COMMAND_FLAG_SOURCE_CONSOLE		1
// command was entered by script
#define COMMAND_FLAG_SOURCE_SCRIPT		2
// command was sent by MQTT
#define COMMAND_FLAG_SOURCE_MQTT		4
// command was sent by HTTP cmnd GET
#define COMMAND_FLAG_SOURCE_HTTP		8
// command was sent by TCP CMD
#define COMMAND_FLAG_SOURCE_TCP			16
// command was sent by IR
#define COMMAND_FLAG_SOURCE_IR			32
// command was sent by OBK Tele requester
#define COMMAND_FLAG_SOURCE_TELESENDER	64

extern bool g_powersave;

//
void CMD_Init_Early();
void CMD_Init_Delayed();
void CMD_FreeAllCommands();
void CMD_RunUartCmndIfRequired();
void CMD_RegisterCommand(const char* name, commandHandler_t handler,  void* context);
commandResult_t CMD_ExecuteCommand(const char* s, int cmdFlags);
commandResult_t CMD_ExecuteCommandArgs(const char* cmd, const char* args, int cmdFlags);
// like a strdup, but will expand constants.
// Please remember to free the returned string
char *CMD_ExpandingStrdup(const char *in);

enum EventCode {
	CMD_EVENT_NONE,
	// per-pins event (no value, only trigger action)
	// This is for Buttons
	CMD_EVENT_PIN_ONCLICK,
	CMD_EVENT_PIN_ONDBLCLICK,
	CMD_EVENT_PIN_ONHOLD,
	CMD_EVENT_PIN_ONHOLDSTART,
	// for simple event on any change (not with given value)
	CMD_EVENT_CHANNEL_ONCHANGE,
	// change events (with a value, so event can trigger only when
	// argument becomes larger than a given threshold, or lower, etc)
	CMD_EVENT_CHANGE_CHANNEL0,
	CMD_EVENT_CHANGE_CHANNEL63 = CMD_EVENT_CHANGE_CHANNEL0 + 63,
	// change events for custom values (non-channels)
	CMD_EVENT_CHANGE_VOLTAGE, // must match order in drv_bl0942.c
	CMD_EVENT_CHANGE_CURRENT,
	CMD_EVENT_CHANGE_POWER,
	CMD_EVENT_CHANGE_CONSUMPTION_TOTAL,
	CMD_EVENT_CHANGE_CONSUMPTION_LAST_HOUR,

	// this is for ToggleChannelOnToggle
	CMD_EVENT_PIN_ONTOGGLE,

	// Argument is a string
	// You can fire an event when TuyaMCU or something receives given string
	CMD_EVENT_ON_UART,

	// IR events
	// There will be separate event types for common IR protocol,
	// but we will also have a generic IR event with protocol name or index.
	// I have decided to have both, because per-protocol events with
	// a single integer arguments can be faster and easier to write,
	// and we have a whole byte for event index so they don't
	// add much overheat. So...
	CMD_EVENT_IR_SAMSUNG, // Argument: [Address][Command]
	CMD_EVENT_IR_RC5, // Argument: [Address][Command]
	CMD_EVENT_IR_RC6, // Argument: [Address][Command]
	CMD_EVENT_IR_SONY, // Argument: [Address][Command]
	CMD_EVENT_IR_PANASONIC, // Argument: [Address][Command]
	CMD_EVENT_IR_SAMSUNG_LG, // Argument: [Address][Command]
	CMD_EVENT_IR_SHARP, // Argument: [Address][Command]
	CMD_EVENT_IR_NEC, // Argument: [Address][Command]

	//CMD_EVENT_GENERIC, // TODO?

	CMD_EVENT_MQTT_STATE,

	// for buttons
	CMD_EVENT_PIN_ONRELEASE,

	CMD_EVENT_PIN_ONPRESS,

	CMD_EVENT_LED_STATE,

	CMD_EVENT_IPCHANGE,

	CMD_EVENT_WIFI_STATE, // Argument: [HALWifiStatus_t]

	CMD_EVENT_PIN_ON3CLICK,
	CMD_EVENT_PIN_ON4CLICK,

	CMD_EVENT_CHANGE_NOPINGTIME,

	CMD_EVENT_TUYAMCU_PARSED, // Argument: TuyaMCU packet type

	// must be lower than 256
	CMD_EVENT_MAX_TYPES
};


// the slider control in the UI emits values
//in the range from 154-500 (defined
//in homeassistant/util/color.py as HASS_COLOR_MIN and HASS_COLOR_MAX).

#define HASS_TEMPERATURE_MIN 154
#define HASS_TEMPERATURE_MAX 500
#define KELVIN_TEMPERATURE_MIN 2000
#define KELVIN_TEMPERATURE_MAX 6500

// In general, LED can be in two modes:
// - Temperature (Cool and Warm LEDs are on)
// - RGB (R G B LEDs are on)
// This is just like in Tuya.
// The third mode, "All", was added by me for testing.
enum LightMode {
	Light_Temperature,
	Light_RGB,
	Light_All,
};

#define TOKENIZER_ALLOW_QUOTES					1
#define TOKENIZER_DONT_EXPAND					2
// expand constants within whole command and not per-argumenet
#define TOKENIZER_ALTERNATE_EXPAND_AT_START		4

// cmd_tokenizer.c
int Tokenizer_GetArgsCount();
bool Tokenizer_CheckArgsCountAndPrintWarning(const char *cmdStr, int reqCount);
const char* Tokenizer_GetArg(int i);
const char* Tokenizer_GetArgFrom(int i);
int Tokenizer_GetArgInteger(int i);
bool Tokenizer_IsArgInteger(int i);
float Tokenizer_GetArgFloat(int i);
int Tokenizer_GetArgIntegerRange(int i, int rangeMax, int rangeMin);
void Tokenizer_TokenizeString(const char* s, int flags);
// cmd_repeatingEvents.c
void RepeatingEvents_Init();
void RepeatingEvents_OnEverySecond();
void SIM_GenerateRepeatingEventsDesc(char *o, int outLen);
// cmd_eventHandlers.c
void EventHandlers_Init();
// This is useful to fire an event when a certain UART string command is received.
// For example, you can fire an event while getting 55 AA 01 02 00 03 FF 01 01 06  on UART..
void EventHandlers_FireEvent_String(byte eventCode, const char* argument);
// This is useful to fire an event when, for example, a button is pressed.
// Then eventCode is a BUTTON_PRESS and argument is a button index.
void EventHandlers_FireEvent(byte eventCode, int argument);
void EventHandlers_FireEvent2(byte eventCode, int argument, int argument2);
void EventHandlers_FireEvent3(byte eventCode, int argument, int argument2, int argument3);
// This is more advanced event handler. It will only fire handlers when a variable state changes from one to another.
// For example, you can watch for Voltage from BL0942 to change below 230, and it will fire event only when it becomes below 230.
void EventHandlers_ProcessVariableChange_Integer(byte eventCode, int oldValue, int newValue);
int EventHandlers_GetActiveCount();
// cmd_tasmota.c
int taslike_commands_init();
// cmd_newLEDDriver.c
void NewLED_InitCommands();
void NewLED_RestoreSavedStateIfNeeded();
float LED_GetDimmer();
void LED_AddDimmer(int iVal, int addMode, int minValue);
void LED_AddTemperature(int iVal, bool wrapAroundInsteadOfClamp);
void LED_NextDimmerHold();
void LED_NextTemperatureHold();
int LED_IsRunningDriver();
float LED_GetTemperature();
void LED_SetTemperature(int tmpInteger, bool bApply);
float LED_GetTemperature0to1Range();
void LED_SetTemperature0to1Range(float f);
void LED_SetDimmer(int iVal);
commandResult_t LED_SetBaseColor(const void* context, const char* cmd, const char* args, int bAll);
void LED_SetFinalCW(byte c, byte w);
void LED_SetFinalRGB(byte r, byte g, byte b);
void LED_SetFinalRGBCW(byte* rgbcw);
void LED_GetFinalChannels100(byte* rgbcw);
void LED_GetFinalHSV(int* hsv);
void LED_GetFinalRGBCW(byte* rgbcw);
// color indices are as in Tasmota
void LED_SetColorByIndex(int index);
void LED_NextColor();
void LED_ToggleEnabled();
bool LED_IsLedDriverChipRunning();
bool LED_IsLEDRunning();
void LED_SetEnableAll(int bEnable);
int LED_GetEnableAll();
void LED_GetBaseColorString(char* s);
int LED_GetMode();
float LED_GetHue();
float LED_GetSaturation();
float LED_GetGreen255();
float LED_GetRed255();
float LED_GetBlue255();
void LED_RunQuickColorLerp(int deltaMS);
OBK_Publish_Result sendFinalColor();
OBK_Publish_Result sendColorChange();
OBK_Publish_Result LED_SendEnableAllState();
OBK_Publish_Result LED_SendDimmerChange();
OBK_Publish_Result sendTemperatureChange();
OBK_Publish_Result LED_SendCurrentLightMode();
void LED_ResetGlobalVariablesToDefaults();
// cmd_test.c
int CMD_InitTestCommands();
// cmd_channels.c
void CMD_InitChannelCommands();
// cmd_send.c
int CMD_InitSendCommands();
// cmd_tcp.c
void CMD_StartTCPCommandLine();
// cmd_script.c
int CMD_GetCountActiveScriptThreads();

void SVM_RunThreads(int deltaMS);
void CMD_InitScripting();
byte* LFS_ReadFile(const char* fname);

commandResult_t CMD_ClearAllHandlers(const void *context, const char *cmd, const char *args, int cmdFlags);
commandResult_t RepeatingEvents_Cmd_ClearRepeatingEvents(const void *context, const char *cmd, const char *args, int cmdFlags);
commandResult_t CMD_resetSVM(const void *context, const char *cmd, const char *args, int cmdFlags);
int RepeatingEvents_GetActiveCount();

#endif // __CMD_PUBLIC_H__
