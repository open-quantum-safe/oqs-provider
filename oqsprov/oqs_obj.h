/* Serialized OID's */
static const unsigned char so[11] = {
    0x2B,0x06,0x01,0x04,0x01,0x02,0x82,0x0B,0x07,0x04,0x04,  /* [ 0] OBJ_dilithium2 */
};

#define OQS_NUM_NID 1

static const ASN1_OBJECT oqs_nid_objs[OQS_NUM_NID] = {
    {"dilithium2", "dilithium2", NID_dilithium2, 11, &so[0]},
};

