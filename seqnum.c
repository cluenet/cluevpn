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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seqnum.h"

void seqnum_init_state(seqnum_state_t *state) {
	state->last_seqnum = 0;
	state->last_reset_time = 0;
	state->last_recv_time = 0;
	state->recv_window_pos = 0;
	memset(state->recv_window, 0, SEQNUM_WINDOW_SIZE);
}

char seqnum_newseqvalid(seqnum_state_t *state, unsigned int cseqnum, unsigned int crecvtime) {
	int i;
	int windowbit;
	// If the current recv time is before the last reset time, something fishy is going on - disallow it
	if(crecvtime < state->last_reset_time) return 0;
	// If the new seqnum is larger than the last, it's allowed
	if(cseqnum > state->last_seqnum) {
		// Advance the recv window position
		// If the new sequence number is much larger than the old one, just wipe out the window instead of iterating through multiple times
		if(cseqnum > state->last_seqnum + SEQNUM_WINDOW_SIZE * 8) {
			state->recv_window_pos = 0;
			memset(state->recv_window, 0, SEQNUM_WINDOW_SIZE);
		} else if(cseqnum == state->last_seqnum + 1) {
			// If the new seqnum is exactly one higher than the last one, skip the loop
			state->recv_window_pos++;
			if(state->recv_window_pos >= SEQNUM_WINDOW_SIZE * 8) state->recv_window_pos = 0;
			SEQNUM_SET_WINDOW_BIT(state->recv_window, state->recv_window_pos);
		} else {
			// Loop through all the sequence numbers that were skipped (not including the current received one), and set the bit for each one to 0
			for(i = 0; i < cseqnum - state->last_seqnum - 1; i++) {
				state->recv_window_pos++;
				if(state->recv_window_pos >= SEQNUM_WINDOW_SIZE * 8) state->recv_window_pos = 0;
				SEQNUM_CLEAR_WINDOW_BIT(state->recv_window, state->recv_window_pos);
			}
			// Advance position once more and set bit (corresponding to current received seqnum)
			state->recv_window_pos++;
			if(state->recv_window_pos >= SEQNUM_WINDOW_SIZE * 8) state->recv_window_pos = 0;
			SEQNUM_SET_WINDOW_BIT(state->recv_window, state->recv_window_pos);
		}
		// Update the last_seqnum and last_recv_time
		state->last_seqnum = cseqnum;
		state->last_recv_time = crecvtime;
		// Return allowed
		return 1;
	}
	// If there's a seqnum that's less than or equal to the last seqnum, but has a greater recv time, it's valid, and triggers a seqnum reset
	if(state->last_seqnum >= cseqnum && crecvtime > state->last_recv_time) {
		state->last_seqnum = cseqnum;
		state->last_reset_time = crecvtime;
		state->last_recv_time = crecvtime;
		state->recv_window_pos = 0;
		memset(state->recv_window, 0, SEQNUM_WINDOW_SIZE);
		SEQNUM_SET_WINDOW_BIT(state->recv_window, 0);
		return 1;
	}
	// If there's a seqnum that's significantly less (out of the window) of the last seqnum, it can't be in the window, and is just rejected
	if(state->last_seqnum >= cseqnum + SEQNUM_WINDOW_SIZE * 8) return 0;
	// Check the window to see if this sequence number has been received yet
	windowbit = state->recv_window_pos - (state->last_seqnum - cseqnum);
	while(windowbit < 0) windowbit += SEQNUM_WINDOW_SIZE * 8;
	if(!SEQNUM_GET_WINDOW_BIT(state->recv_window, windowbit)) {
		SEQNUM_SET_WINDOW_BIT(state->recv_window, windowbit);
		return 1;
	}
	// Default to denying it
	return 0;
}

/*
void _seqnum_test() {
	seqnum_state_t ss;
	int i, r;
	unsigned int nseq, ntime;
	seqnum_init_state(&ss);
	while(1) {
		printf("Last Sequence Number: %u  Last Received Time: %u  Last Reset Time: %u\n", ss.last_seqnum, ss.last_recv_time, ss.last_reset_time);
		printf("Window (Position %d, Size %d):\n", ss.recv_window_pos, SEQNUM_WINDOW_SIZE * 8);
		for(i = 0; i < ss.recv_window_pos; i++) printf(" ");
		printf("v\n");
		for(i = 0; i < SEQNUM_WINDOW_SIZE * 8; i++) printf("%d", SEQNUM_GET_WINDOW_BIT(ss.recv_window, i));
		printf("\n");
		printf("New sequence number (SeqNum Time):\n");
		scanf("%u %u", &nseq, &ntime);
		r = seqnum_newseqvalid(&ss, nseq, ntime);
		if(r) printf("Accepted\n"); else printf("Rejected\n");
		printf("\n");
	}
}
*/

