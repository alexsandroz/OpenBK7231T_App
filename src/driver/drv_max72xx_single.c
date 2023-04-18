#include "../new_common.h"
#include "../new_pins.h"
#include "../new_cfg.h"
// Commands register, execution API and cmd tokenizer
#include "../cmnds/cmd_public.h"
#include "../mqtt/new_mqtt.h"
#include "../logging/logging.h"
#include "../hal/hal_pins.h"
#include "drv_public.h"
#include "drv_local.h"
#include "drv_max72xx_internal.h"

static max72XX_t *g_max = 0;

unsigned char testhello[4][8] = {
  {
	0b10000010,
	0b01000100,
	0b00101000,
	0b00010000,
	0b00010000,
	0b00010000,
	0b00010000,
	0b00010000,
  },
  {
	0b10000010,
	0b01000100,
	0b00101000,
	0b00010000,
	0b00010000,
	0b00010000,
	0b00010000,
	0b00010000,
  },
  {
	0b01111110,
	0b01000000,
	0b01000000,
	0b01111110,
	0b01000000,
	0b01000000,
	0b01000000,
	0b01111110,
  },
  {
	0b10000001,
	0b10000001,
	0b10000001,
	0b10000001,
	0b11111111,
	0b10000001,
	0b10000001,
	0b10000001,
  },
};

byte g_font[] =
{
	0,    // 0 - Unused
	0,    // 1 - Unused
	0,    // 2 - Unused
	0,    // 3 - Unused
	0,    // 4 - Unused
	0,    // 5 - Unused
	0,    // 6 - Unused
	0,    // 7 - Unused
	0,    // 8 - Unused
	0,    // 9 - Unused
	0,    // 10 - Unused
	0,    // 11 - Unused
	0,    // 12 - Unused
	0,    // 13 - Unused
	0,    // 14 - Unused
	0,    // 15 - Unused
	0,    // 16 - Unused
	0,    // 17 - Unused
	0,    // 18 - Unused
	0,    // 19 - Unused
	0,    // 20 - Unused
	0,    // 21 - Unused
	0,    // 22 - Unused
	0,    // 23 - Unused
	0,    // 24 - Unused
	0,    // 25 - Unused
	0,    // 26 - Unused
	0,    // 27 - Unused
	0,    // 28 - Unused
	0,    // 29 - Unused
	0,    // 30 - Unused
	0,    // 31 - Unused
	2, 0, 0,                  // 32 - Space
	1, 95,                    // 33 - !
	3, 7, 0, 7,               // 34 - "
	5, 20, 127, 20, 127, 20,  // 35 - #
	5, 36, 42, 127, 42, 18,   // 36 - $
	5, 35, 19, 8, 100, 98,    // 37 - %
	5, 54, 73, 86, 32, 80,    // 38 - &
	2, 4, 3,                  // 39
	3, 28, 34, 65,            // 40 - (
	3, 65, 34, 28,            // 41 - )
	5, 42, 28, 127, 28, 42,   // 42 - *
	5, 8, 8, 62, 8, 8,        // 43 - +
	2, 128, 96,               // 44 - ,
	5, 8, 8, 8, 8, 8,         // 45 - -
	2, 96, 96,                // 46 - .
	5, 32, 16, 8, 4, 2,       // 47 - /
	5, 62, 81, 73, 69, 62,    // 48 - 0
	3, 66, 127, 64,           // 49 - 1
	5, 114, 73, 73, 73, 70,   // 50 - 2
	5, 33, 65, 73, 77, 51,    // 51 - 3
	5, 24, 20, 18, 127, 16,   // 52 - 4
	5, 39, 69, 69, 69, 57,    // 53 - 5
	5, 60, 74, 73, 73, 49,    // 54 - 6
	5, 65, 33, 17, 9, 7,      // 55 - 7
	5, 54, 73, 73, 73, 54,    // 56 - 8
	5, 70, 73, 73, 41, 30,    // 57 - 9
	1, 20,                    // 58 - :
	2, 128, 104,              // 59 - ;
	4, 8, 20, 34, 65,         // 60 - <
	5, 20, 20, 20, 20, 20,    // 61 - =
	4, 65, 34, 20, 8,         // 62 - >
	5, 2, 1, 89, 9, 6,        // 63 - ?
	5, 62, 65, 93, 89, 78,    // 64 - @
	5, 124, 18, 17, 18, 124,  // 65 - A
	5, 127, 73, 73, 73, 54,   // 66 - B
	5, 62, 65, 65, 65, 34,    // 67 - C
	5, 127, 65, 65, 65, 62,   // 68 - D
	5, 127, 73, 73, 73, 65,   // 69 - E
	5, 127, 9, 9, 9, 1,       // 70 - F
	5, 62, 65, 65, 81, 115,   // 71 - G
	5, 127, 8, 8, 8, 127,     // 72 - H
	3, 65, 127, 65,           // 73 - I
	5, 32, 64, 65, 63, 1,     // 74 - J
	5, 127, 8, 20, 34, 65,    // 75 - K
	5, 127, 64, 64, 64, 64,   // 76 - L
	5, 127, 2, 28, 2, 127,    // 77 - M
	5, 127, 4, 8, 16, 127,    // 78 - N
	5, 62, 65, 65, 65, 62,    // 79 - O
	5, 127, 9, 9, 9, 6,       // 80 - P
	5, 62, 65, 81, 33, 94,    // 81 - Q
	5, 127, 9, 25, 41, 70,    // 82 - R
	5, 38, 73, 73, 73, 50,    // 83 - S
	5, 3, 1, 127, 1, 3,       // 84 - T
	5, 63, 64, 64, 64, 63,    // 85 - U
	5, 31, 32, 64, 32, 31,    // 86 - V
	5, 63, 64, 56, 64, 63,    // 87 - W
	5, 99, 20, 8, 20, 99,     // 88 - X
	5, 3, 4, 120, 4, 3,       // 89 - Y
	5, 97, 89, 73, 77, 67,    // 90 - Z
	3, 127, 65, 65,           // 91 - [
	5, 2, 4, 8, 16, 32,       // 92 - \'
	3, 65, 65, 127,           // 93 - ]
	5, 4, 2, 1, 2, 4,         // 94 - ^
	5, 64, 64, 64, 64, 64,    // 95 - _
	2, 3, 4,                  // 96 - `
	5, 32, 84, 84, 120, 64,   // 97 - a
	5, 127, 40, 68, 68, 56,   // 98 - b
	5, 56, 68, 68, 68, 40,    // 99 - c
	5, 56, 68, 68, 40, 127,   // 100 - d
	5, 56, 84, 84, 84, 24,    // 101 - e
	4, 8, 126, 9, 2,          // 102 - f
	5, 24, 164, 164, 156, 120,// 103 - g
	5, 127, 8, 4, 4, 120,     // 104 - h
	3, 68, 125, 64,           // 105 - i
	4, 64, 128, 128, 122,     // 106 - j
	4, 127, 16, 40, 68,       // 107 - k
	3, 65, 127, 64,           // 108 - l
	5, 124, 4, 120, 4, 120,   // 109 - m
	5, 124, 8, 4, 4, 120,     // 110 - n
	5, 56, 68, 68, 68, 56,    // 111 - o
	5, 252, 24, 36, 36, 24,   // 112 - p
	5, 24, 36, 36, 24, 252,   // 113 - q
	5, 124, 8, 4, 4, 8,       // 114 - r
	5, 72, 84, 84, 84, 36,    // 115 - s
	4, 4, 63, 68, 36,         // 116 - t
	5, 60, 64, 64, 32, 124,   // 117 - u
	5, 28, 32, 64, 32, 28,    // 118 - v
	5, 60, 64, 48, 64, 60,    // 119 - w
	5, 68, 40, 16, 40, 68,    // 120 - x
	5, 76, 144, 144, 144, 124,// 121 - y
	5, 68, 100, 84, 76, 68,   // 122 - z
	3, 8, 54, 65,             // 123 - {
	1, 119,                   // 124 - |
	3, 65, 54, 8,             // 125 - }
	5, 2, 1, 2, 4, 2,         // 126 - ~
	0,                        // 127 - Unused
	6, 20, 62, 85, 85, 65, 34,// 128 - Euro sign
	0,                        // 129 - Not used
	2, 128, 96,               // 130 - Single low 9 quotation mark
	5, 192, 136, 126, 9, 3,   // 131 - f with hook
	4, 128, 96, 128, 96,      // 132 - Single low 9 quotation mark
	8, 96, 96, 0, 96, 96, 0, 96, 96,   // 133 - Horizontal ellipsis
	3, 4, 126, 4,             // 134 - Dagger
	3, 20, 126, 20,           // 135 - Double dagger
	4, 2, 1, 1, 2,            // 136 - Modifier circumflex
	7, 35, 19, 104, 100, 2, 97, 96,    // 137 - Per mille sign
	5, 72, 85, 86, 85, 36,    // 138 - S with caron
	3, 8, 20, 34,             // 139 - < quotation
	6, 62, 65, 65, 127, 73, 73,        // 140 - OE
	0,                        // 141 - Not used
	5, 68, 101, 86, 77, 68,   // 142 - z with caron
	0,                        // 143 - Not used
	0,                        // 144 - Not used
	2, 3, 4,                  // 145 - Left single quote mark
	2, 4, 3,                  // 146 - Right single quote mark
	4, 3, 4, 3, 4,            // 147 - Left double quote marks
	4, 4, 3, 4, 3,            // 148 - Right double quote marks
	4, 0, 24, 60, 24,         // 149 - Bullet Point
	3, 8, 8, 8,               // 150 - En dash
	5, 8, 8, 8, 8, 8,         // 151 - Em dash
	4, 2, 1, 2, 1,            // 152 - Small ~
	7, 1, 15, 1, 0, 15, 2, 15,// 153 - TM
	5, 72, 85, 86, 85, 36,    // 154 - s with caron
	3, 34, 20, 8,             // 155 - > quotation
	7, 56, 68, 68, 124, 84, 84, 8,     // 156 - oe
	0,                        // 157 - Not used
	5, 68, 101, 86, 77, 68,   // 158 - z with caron
	5, 12, 17, 96, 17, 12,    // 159 - Y diaresis
	2, 0, 0,                  // 160 - Non-breaking space
	1, 125,                   // 161 - Inverted !
	5, 60, 36, 126, 36, 36,   // 162 - Cent sign
	5, 72, 126, 73, 65, 102,  // 163 - Pound sign
	5, 34, 28, 20, 28, 34,    // 164 - Currency sign
	5, 43, 47, 252, 47, 43,   // 165 - Yen
	1, 119,                   // 166 - |
	4, 102, 137, 149, 106,    // 167 - Section sign
	3, 1, 0, 1,               // 168 - Spacing diaresis
	7, 62, 65, 93, 85, 85, 65, 62,    // 169 - Copyright
	3, 13, 13, 15,            // 170 - Feminine Ordinal Ind.
	5, 8, 20, 42, 20, 34,     // 171 - <<
	5, 8, 8, 8, 8, 56,        // 172 - Not sign
	0,                        // 173 - Soft Hyphen
	7, 62, 65, 127, 75, 117, 65, 62,    // 174 - Registered Trademark
	5, 1, 1, 1, 1, 1,         // 175 - Spacing Macron Overline
	3, 2, 5, 2,               // 176 - Degree
	5, 68, 68, 95, 68, 68,    // 177 - +/-
	3, 25, 21, 19,            // 178 - Superscript 2
	3, 17, 21, 31,            // 179 - Superscript 3
	2, 2, 1,                  // 180 - Acute accent
	4, 252, 64, 64, 60,       // 181 - micro (mu)
	5, 6, 9, 127, 1, 127,     // 182 - Paragraph Mark
	2, 24, 24,                // 183 - Middle Dot
	3, 128, 128, 96,          // 184 - Spacing sedilla
	2, 2, 31,                 // 185 - Superscript 1
	4, 6, 9, 9, 6,            // 186 - Masculine Ordinal Ind.
	5, 34, 20, 42, 20, 8,     // 187 - >>
	6, 64, 47, 16, 40, 52, 250,        // 188 - 1/4
	6, 64, 47, 16, 200, 172, 186,      // 189 - 1/2
	6, 85, 53, 31, 40, 52, 250,        // 190 - 3/4
	5, 48, 72, 77, 64, 32,    // 191 - Inverted ?
	5, 120, 20, 21, 22, 120,  // 192 - A grave
	5, 120, 22, 21, 20, 120,  // 193 - A acute
	5, 122, 21, 21, 21, 122,  // 194 - A circumflex
	5, 120, 22, 21, 22, 121,  // 195 - A tilde
	5, 120, 21, 20, 21, 120,  // 196 - A diaresis
	5, 120, 20, 21, 20, 120,  // 197 - A ring above
	6, 124, 10, 9, 127, 73, 73,   // 198 - AE
	5, 30, 161, 161, 97, 18,  // 199 - C sedilla
	4, 124, 85, 86, 68,       // 200 - E grave
	4, 124, 86, 85, 68,       // 201 - E acute
	4, 126, 85, 85, 70,       // 202 - E circumflex
	4, 124, 85, 84, 69,       // 203 - E diaresis
	3, 68, 125, 70,           // 204 - I grave
	3, 68, 126, 69,           // 205 - I acute
	3, 70, 125, 70,           // 206 - I circumplex
	3, 69, 124, 69,           // 207 - I diaresis
	6, 4, 127, 69, 65, 65, 62,// 208 - Capital Eth
	5, 124, 10, 17, 34, 125,  // 209 - N tilde
	5, 56, 68, 69, 70, 56,    // 210 - O grave
	5, 56, 70, 69, 68, 56,    // 211 - O acute
	5, 58, 69, 69, 69, 58,    // 212 - O circumflex
	5, 56, 70, 69, 70, 57,    // 213 - O tilde
	5, 56, 69, 68, 69, 56,    // 214 - O diaresis
	5, 34, 20, 8, 20, 34,     // 215 - Multiplication sign
	7, 64, 62, 81, 73, 69, 62, 1,  // 216 - O slashed
	5, 60, 65, 66, 64, 60,    // 217 - U grave
	5, 60, 64, 66, 65, 60,    // 218 - U acute
	5, 58, 65, 65, 65, 58,    // 219 - U circumflex
	5, 60, 65, 64, 65, 60,    // 220 - U diaresis
	5, 12, 16, 98, 17, 12,    // 221 - Y acute
	4, 127, 18, 18, 12,       // 222 - Capital thorn
	4, 254, 37, 37, 26,       // 223 - Small letter sharp S
	5, 32, 84, 85, 122, 64,   // 224 - a grave
	5, 32, 84, 86, 121, 64,   // 225 - a acute
	5, 34, 85, 85, 121, 66,   // 226 - a circumflex
	5, 32, 86, 85, 122, 65,   // 227 - a tilde
	5, 32, 85, 84, 121, 64,   // 228 - a diaresis
	5, 32, 84, 85, 120, 64,   // 229 - a ring above
	7, 32, 84, 84, 124, 84, 84, 8,     // 230 - ae
	5, 24, 36, 164, 228, 40,  // 231 - c sedilla
	5, 56, 84, 85, 86, 88,    // 232 - e grave
	5, 56, 84, 86, 85, 88,    // 233 - e acute
	5, 58, 85, 85, 85, 90,    // 234 - e circumflex
	5, 56, 85, 84, 85, 88,    // 235 - e diaresis
	3, 68, 125, 66,           // 236 - i grave
	3, 68, 126, 65,           // 237 - i acute
	3, 70, 125, 66,           // 238 - i circumflex
	3, 69, 124, 65,           // 239 - i diaresis
	4, 48, 75, 74, 61,        // 240 - Small eth
	4, 122, 9, 10, 113,       // 241 - n tilde
	5, 56, 68, 69, 70, 56,    // 242 - o grave
	5, 56, 70, 69, 68, 56,    // 243 - o acute
	5, 58, 69, 69, 69, 58,    // 244 - o circumflex
	5, 56, 70, 69, 70, 57,    // 245 - o tilde
	5, 56, 69, 68, 69, 56,    // 246 - o diaresis
	5, 8, 8, 42, 8, 8,        // 247 - Division sign
	6, 64, 56, 84, 76, 68, 58,// 248 - o slashed
	5, 60, 65, 66, 32, 124,   // 249 - u grave
	5, 60, 64, 66, 33, 124,   // 250 - u acute
	5, 58, 65, 65, 33, 122,   // 251 - u circumflex
	5, 60, 65, 64, 33, 124,   // 252 - u diaresis
	4, 156, 162, 161, 124,    // 253 - y acute
	4, 252, 72, 72, 48,       // 254 - small thorn
	4, 157, 160, 160, 125,    // 255 - y diaresis
	255,
};

byte *MAX_GetFontStart(byte code) {
	byte *p;
	byte current;

	current = 0;
	p = g_font;

	while (*p != 255) {
		if (code == current) {
			return p;
		}
		// skip the font data
		p += *p;
		// skip always one byte of font count itself
		p++;
		current++;
	}
	return 0;
}
void MAX72XX_print(max72XX_t *led, int ofs, const char *p) {
	byte *font;
	byte zero = 0;

	while (*p) {
		font = MAX_GetFontStart(*p);
		if (font) {
			MAX72XX_displayArray(led, font+1, *font, ofs);
			ofs += *font;
			MAX72XX_displayArray(led, &zero, 1, ofs);
			ofs++;
		}
		p++;
	}
}
// backlog startDriver MAX72XX; MAX72XX_Setup 0 1 26
static commandResult_t DRV_MAX72XX_Setup(const void *context, const char *cmd, const char *args, int flags) {
	int din;
	int cs;
	int clk;
	int devices;

	Tokenizer_TokenizeString(args, 0);

	clk = Tokenizer_GetArgInteger(0);
	cs = Tokenizer_GetArgInteger(1);
	din = Tokenizer_GetArgInteger(2);
	devices = Tokenizer_GetArgInteger(3);
	//clk = 9;
	//cs = 14;
	//din = 8;

	if (devices == 0) {
		devices = 4;
	}

	g_max = MAX72XX_alloc();

	MAX72XX_setupPins(g_max, cs, clk, din, devices);
	MAX72XX_init(g_max);
	MAX72XX_displayArray(g_max, &testhello[0][0], 32, 0);
	MAX72XX_refresh(g_max);

	return CMD_RES_OK;
}
static commandResult_t DRV_MAX72XX_Scroll(const void *context, const char *cmd, const char *args, int flags) {
	if (g_max == 0)
		return CMD_RES_ERROR;
	MAX72XX_shift(g_max,1);
	MAX72XX_refresh(g_max);

	return CMD_RES_OK;
}
static commandResult_t DRV_MAX72XX_Print(const void *context, const char *cmd, const char *args, int flags) {
	int ofs;
	//const char *s;
	if (g_max == 0)
		return CMD_RES_ERROR;

	//Tokenizer_TokenizeString(args, 0);

	ofs = 0;

	//ofs = Tokenizer_GetArgInteger(0);
	//s = Tokenizer_GetArg(1);

	MAX72XX_print(g_max, ofs, args);
	MAX72XX_rotate90CW(g_max);
	MAX72XX_refresh(g_max);

	return CMD_RES_OK;
}
/*
again:
MAX72XX_Print 123456
delay_s 0.5
MAX72XX_Print abcdef
delay_s 0.5
MAX72XX_Print ABCDEF
delay_s 0.5
MAX72XX_Print HeyHey
delay_s 0.5
MAX72XX_Print a!a!a!a!
delay_s 0.5

goto again



*/
// backlog startDriver MAX72XX; MAX72XX_Setup
// MAX72XX_Print 0 1234567
// backlog startDriver MAX72XX; MAX72XX_Setup; MAX72XX_Print 0 1234567
void DRV_MAX72XX_Init() {

	//cmddetail:{"name":"MAX72XX_Setup","args":"[Value]",
	//cmddetail:"descr":"Sets the maximum current for LED driver.",
	//cmddetail:"fn":"SM2135_Current","file":"driver/drv_sm2135.c","requires":"",
	//cmddetail:"examples":""}
	CMD_RegisterCommand("MAX72XX_Setup", DRV_MAX72XX_Setup, NULL);
	//cmddetail:{"name":"MAX72XX_Scroll","args":"DRV_MAX72XX_Scroll",
	//cmddetail:"descr":"",
	//cmddetail:"fn":"NULL);","file":"driver/drv_max72xx_single.c","requires":"",
	//cmddetail:"examples":""}
	CMD_RegisterCommand("MAX72XX_Scroll", DRV_MAX72XX_Scroll, NULL);
	//cmddetail:{"name":"MAX72XX_Print","args":"DRV_MAX72XX_Print",
	//cmddetail:"descr":"",
	//cmddetail:"fn":"NULL);","file":"driver/drv_max72xx_single.c","requires":"",
	//cmddetail:"examples":""}
	CMD_RegisterCommand("MAX72XX_Print", DRV_MAX72XX_Print, NULL);
}





