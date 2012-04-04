/*
 * Copyright 2009 Christopher Breneman
 *
 * This file is part of ClueVPN.
 *
 * ClueVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ClueVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ClueVPN.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef _SEQNUM_H
#define _SEQNUM_H

// 16 bytes, with one bit per window entry, = 128 entries
#define SEQNUM_WINDOW_SIZE 16

typedef struct {
	unsigned int last_seqnum;
	unsigned int last_reset_time;
	unsigned int last_recv_time;
	unsigned int recv_window_pos;	// Points to the bit in recv_window corresponding to last_seqnum
	unsigned char recv_window[SEQNUM_WINDOW_SIZE];
} seqnum_state_t;

#define SEQNUM_SET_WINDOW_BIT(window, bitnum) window[bitnum / 8] |= (0x80 >> (bitnum % 8))
#define SEQNUM_CLEAR_WINDOW_BIT(window, bitnum) window[bitnum / 8] &= ~(0x80 >> (bitnum % 8))
#define SEQNUM_GET_WINDOW_BIT(window, bitnum) ((window[bitnum / 8] & (0x80 >> (bitnum % 8))) ? 1 : 0)

void seqnum_init_state(seqnum_state_t *state);
char seqnum_newseqvalid(seqnum_state_t *state, unsigned int cseqnum, unsigned int crecvtime);

#endif
