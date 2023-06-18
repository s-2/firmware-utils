/* SPDX-License-Identifier: GPL-2.0-only */

const unsigned char key1[] =
	"\x35\x87\x90\x03\x45\x19\xf8\xc8\x23\x5d\xb6\x49\x28\x39\xa7\x3f";

const unsigned char key2[] =
	"\xc8\xd3\x2f\x40\x9c\xac\xb3\x47\xc8\xd2\x6f\xdc\xb9\x09\x0b\x3c";

const unsigned char iv[] =
	"\x98\xc9\xd8\xf0\x13\x3d\x06\x95\xe2\xa7\x09\xc8\xb6\x96\x82\xd4";

const unsigned char salt[] =
	"\x67\xc6\x69\x73\x51\xff\x4a\xec\x29\xcd\xba\xab\xf2\xfb\xe3\x46";

/*
  enk.txt as found in GPL tarball:
  COVR-X1860_GPL_Release/MTK7621_AX1800_BASE/vendors/COVR-X1860/imgkey/enk.txt
*/
const unsigned char enk_covrx1860[] =
	"NE1oIS1lKzkkIzZkbX49KTMsMWFkJXEybjheJiN6KjIwNjgx";

/*
  enk.txt as found in GPL tarball:
  DIR-X3260_GPL_Release/MTK7621_AX1800_BASE/vendors/DIR-X3260/imgkey/enk.txt
*/
const unsigned char enk_dirx3260[] =
	"NF5yKy10JTl+bSkhNj1kTTIkI3FhIyUsJDU0czMyZmR6Jl4jMzI4KjA2Mg==";

#define INTERLEAVE_BLOCK_SIZE	8
const unsigned char interleaving_pattern[INTERLEAVE_BLOCK_SIZE][INTERLEAVE_BLOCK_SIZE] = {
	{2, 5, 7, 4, 0, 6, 1, 3},
	{7, 3, 2, 6, 4, 5, 1, 0},
	{5, 1, 6, 7, 3, 0, 4, 2},
	{0, 3, 7, 6, 5, 4, 2, 1},
	{1, 5, 7, 0, 3, 2, 6, 4},
	{3, 6, 2, 5, 4, 7, 1, 0},
	{6, 0, 5, 1, 3, 4, 2, 7},
	{4, 6, 7, 3, 2, 0, 1, 5}
};

/*
  key.pem as found in GPL tarball, e.g.:
  COVRP2500A1_FW101/COVRP2500_GPL_Release/package/tw-prog.priv/imgcrypt/key.pem
  encrypted with passphrase: "12345678"
*/
const unsigned char key_legacy_pem[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,EAA1FD02CDBC7AA7E62AC821D47823F2

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
-----END RSA PRIVATE KEY-----
)";

/*
  key.pem as found in GPL tarball:
  COVR-X1860_GPL_Release/MTK7621_AX1800_BASE/vendors/COVR-X1860/imgkey/key.pem
  encrypted with passphrase: "12345678"
*/
const unsigned char key_covrx1860_pem[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,34CCF1AEF0C34EAC5FFAE6BCF81ABB8D

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
-----END RSA PRIVATE KEY-----
)";

/*
  key.pem as found in GPL tarball, e.g.:
  DIR-X3260_GPL_Release/MTK7621_AX1800_BASE/vendors/DIR-X3260/imgkey/key.pem
  encrypted with passphrase: "12345678"
*/
const unsigned char key_dirx3260_pem[] = R"(
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,DDAC1FE060CB240242046BDFEEE17E44

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
-----END RSA PRIVATE KEY-----
)";
