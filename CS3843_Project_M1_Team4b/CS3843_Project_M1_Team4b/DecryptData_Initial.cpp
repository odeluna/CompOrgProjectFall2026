// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

void decryptData_01(char* data, int sized)
{
	__asm
	{
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		// Starting_index[round] = (PasswordHash[0] * 256 + PasswordHash[1]) + round * 4
		mov ecx, gNumRounds // get the number of rounds
		shl ecx, 2 // multiply by 4
		mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi
		add ecx, esi // add the address of gPasswordHash to ecx
		movzx eax, byte ptr[ecx] // get the first byte of the password hash and multiply by 256
		shl eax, 8 // shift left by 8 bits (multiply by 256)
		movzx ebx, byte ptr[ecx + 1] // get the second byte of the password hash
		add eax, ebx // add the second byte to the first byte 
		// eax now contains the starting index for the current round - can be used as index for the rest of the program


		xor ecx, ecx
		mov ecx, sized // get the length of the data
		xor ebx, ebx // initialize loop counter

		encrypt_loop :
		cmp ebx, ecx // compare loop counter with data length
			jge DONE // if loop counter >= data length, jump to done (x < datalength)

			mov dl, byte ptr[data + ebx] // get the current byte of data
			mov esi, gptrKey // get the address of the key
			xor dl, byte ptr[esi + eax] // xor with the corresponding byte of the key
			mov byte ptr[data + ebx], dl // store the encrypted byte back to data (data[x] = data[x] ^ key[starting_index + x])
			xor edx, edx // clear edx 
			// end of Milestone 1







			inc ebx // Milestone 1 (x++)

			jmp encrypt_loop // Milestone 1

			DONE :
	}

	return;
} // decryptData_01


void decryptData_02(char* data, int sized)
{
	__asm
	{
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		// Starting_index[round] = (PasswordHash[0] * 256 + PasswordHash[1]) + round * 4

		mov esi, gptrPasswordHash	// put ADDRESS of gPasswordHash into esi
		movzx eax, byte ptr[esi] // get the first byte of the password hash and multiply by 256
		shl eax, 8 // shift left by 8 bits (multiply by 256)
		movzx ebx, byte ptr[esi + 1] // get the second byte of the password hash
		add eax, ebx // add the second byte to the first byte 
		// eax now contains the starting index for the current round - can be used as index for the rest of the program


		mov ecx, sized // get the length of the data
		xor ebx, ebx // initialize loop counter

		mov edi, data // get the address of the data

		encrypt_loop :
		cmp ebx, ecx // compare loop counter with data length
			jge DONE // if loop counter >= data length, jump to done (x < datalength)

			
			// end of Milestone 1

			// Start of Milestone 2

			// #E
			push eax
			xor eax,eax 
			xor edx, edx // clear edx
			push ecx // save ecx (data length) on the stack (I need ecx)
			movzx edx, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			mov eax, edx // copy the value of edx into eax
			and eax, 0x03 // mask eax with 0000 0011 clears first 6 bits of both nibbles
			mov ecx, eax // move the value of eax into ecx (0,1,2, or 3) for the shift
			rol dl, cl // rotate left the value of dl by the value in cl
			mov byte ptr[edi + ebx], dl // store the encrypted byte back to data 
			pop ecx // restore ecx (data length) from the stack
			pop eax

			// #B
			xor edx, edx // clear edx
			push eax
			xor eax, eax
			movzx eax, byte ptr[ebx + edi] // get the current byte of data (data[x] into edi)
			mov dl, byte ptr[gDecodeTable + eax] // get the corresponding byte from the decode table]
			mov byte ptr[edi + ebx], dl // store the encrypted byte back to data (data[x] = gDecodeTable[data[x]])
			pop eax

			// #A
			xor edx, edx // clear edx		
			mov dh, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			mov dl, dh // copy the value of dh into dl
			and dh, 0xEE // mask dh with 0111 0111 clears first bit of both nibbles
			shr dh, 1 // shift right by 1 bit (pattern 0111 0111 becomes 0111 0111)
			and dl, 0x11 // mask dl with 1000 1000 clears last 3 bits of both nibbles
			shl dl, 3 // shift left by 3 bits (pattern 0001	0001 becomes 1000 1000)
			or dl, dh // combine the two nibbles back together (pattern 0111 0111 or 1000 1000 becomes 1111 1111)
			mov byte ptr[edi + ebx], dl // store the encrypted byte back to data (data[x] = data[x] ^ 0xC3)

			// #C
			xor edx, edx // clear edx
			movzx edx, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			xor dl, 0xC3 // flip bits 0,1,6, and 7 of data[x] (edx = data[x] ^ 0xC3)
			mov byte ptr[edi + ebx], dl // store the encrypted byte back to data (data[x] = data[x] ^ 0xC3)

			// #D
			xor edx, edx // clear edx
			push ecx // save ecx (data length) on the stack (I need ecx)
			xor ecx, ecx // clear ecx (this is our final copy)

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x01 // mask dl with 0000 0001 clears first 7 bits of both nibbles
			shl dl, 7 // shift left by 7 bits (pattern 0000 0001 becomes 1000 0000)
			or ecx, edx // set 7th bit of ecx to the 0th bit of data[x] 

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x02 // mask dl with 0000 0010 clears first 6 bits of both nibbles
			shl dl, 5 // shift left by 5 bits (pattern 0000 0010 becomes 0100 0000)
			or ecx, edx // set 6th bit of ecx to the 1st bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x04 // mask dl with 0000 0100 clears first 5 bits of both nibbles
			shl dl, 3 // shift left by 3 bits (pattern 0000 0100 becomes 0010 0000)
			or ecx, edx // set 5th bit of ecx to the 2nd bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x08 // mask dl with 0000 1000 clears first 4 bits of both nibbles
			shl dl, 1 // shift left by 1 bits (pattern 0000 1000 becomes 0001 0000)
			or ecx, edx // set 4th bit of ecx to the 3rd bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x10 // mask dl with 0001 0000 clears first 3 bits of both nibbles
			shr dl, 1 // shift right by 1 bits (pattern 0001 0000 becomes 0000 1000)
			or ecx, edx // set 3rd bit of ecx to the 4th bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x20 // mask dl with 0010 0000 clears first 2 bits of both nibbles
			shr dl, 3 // shift right by 3 bits (pattern 0010 0000 becomes 0000 0100)
			or ecx, edx // set 2nd bit of ecx to the 5th bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x40 // mask dl with 0100 0000 clears first 1 bits of both nibbles
			shr dl, 5 // shift right by 5 bits (pattern 0100 0000 becomes 0000 0010)
			or ecx, edx // set 1st bit of ecx to the 6th bit of data[x]

			mov dl, byte ptr[edi + ebx] // get the current byte of data (data[x] into edx)
			and dl, 0x80 // mask dl with 1000 0000 clears first 0 bits of both nibbles
			shr dl, 7 // shift right by 7 bits (pattern 1000 0000 becomes 0000 0001)
			or ecx, edx // set 0th bit of ecx to the 7th bit of data[x]

			mov byte ptr[edi + ebx], cl // store the encrypted byte back to data (data[x] = ecx)
			pop ecx // restore ecx (data length) from the stack

			mov dl, byte ptr[edi + ebx] // get the current byte of data
			mov esi, gptrKey // get the address of the key
			xor dl, byte ptr[esi + eax] // xor with the corresponding byte of the key
			mov byte ptr[edi + ebx], dl // store the encrypted byte back to data (data[x] = data[x] ^ key[starting_index + x])

			// End of Milestone 2



			inc ebx // Milestone 1 (x++)

			jmp encrypt_loop // Milestone 1

			DONE :
	}

	return;
} // decryptData_02


int decryptData_03(char* data, int sized)
{
	__asm
	{
		nop		// REPLACE THIS WITH YOUR DECRYPT CODE FOR MILESTONE #3
	}

	return 0;
} // decryptData_03
