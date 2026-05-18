package fairplay

const (
	wbStaticConstPageBase       uint64 = 0x1a1305000
	wbStaticVectorConstPageBase uint64 = 0x1a1306000
	wbStaticBranchPageBase      uint64 = 0x1a1308000
	wbStaticPage1309Base        uint64 = 0x1a1309000
	wbStaticPage130ABase        uint64 = 0x1a130a000
	wbStaticPage130CBase        uint64 = 0x1a130c000
	wbStaticPage130DBase        uint64 = 0x1a130d000
	wbStaticPage130EBase        uint64 = 0x1a130e000
	wbStaticPage1311Base        uint64 = 0x1a1311000
	wbStaticPage1314Base        uint64 = 0x1a1314000
	wbStaticPointerTableBase    uint64 = 0x1aeab6000
	wbStaticPageSize            uint64 = 0x1000
)

var wbStaticVectorConstants = [...][2]uint64{
	{0x0000000000000006, 0x0000000000000007},
	{0x0000000000000004, 0x0000000000000005},
	{0x0000000000000002, 0x0000000000000003},
	{0x0000000000000000, 0x0000000000000001},
}

var wbStaticLookupVectorB60 = [2]uint64{0x7bea91fefa7596a0, 0x17dd716edf798ae4}

var wbStaticSeedBranchOffsets = [...]int32{0, 72, 32, 0, 0, 100, 0, 0}

var wbStaticD3B8CWords = [...]uint64{
	0xf13c9ae8c7b7e9d6, 0xb80d52af7671456d,
	0xc2f48c438baadcdd, 0x4f748a406c17c0ea,
	0xd9bce4a8eebe444b, 0xff1dac31efa9cd2b,
	0xf6380ae07fc14d1e, 0x01877bc31c92d2c8,
}

var wbStaticEncodedWordCOffsets = [...]int32{0, 112, 40, 0, 0, 328}

var wbStaticPaddingZeroOffsets = [...]int32{
	60, 0, 64, 0, 808, 0, 56, 0, 0, 52, 60, 0, 0, 44,
}

var wbStaticPage130EBytes942 = [...]byte{
	0x67, 0xbc, 0x54, 0xc0, 0x8e, 0x32, 0x85, 0x1b,
	0x50, 0xd2, 0x12, 0x5f, 0x68, 0xb7, 0x40, 0xa5,
}

var wbStaticPage130DBytesD20 = [...]byte{
	0x00, 0xde, 0x02, 0xfa, 0x89, 0x73, 0x3b, 0x01,
	0xa9, 0x29, 0xf1, 0x43, 0x9c, 0x00, 0x62, 0x51,
	0x20, 0x4a, 0x90, 0x24, 0x78, 0xd7, 0x84, 0xb0,
	0x76, 0xdc, 0x3d, 0xb3, 0xae, 0x13, 0x92, 0x90,
	0xb5, 0xc9, 0xd5, 0x5c, 0xca, 0x43, 0x6b, 0x30,
	0x14, 0x3a, 0xe2, 0xe2, 0x7d, 0x5a, 0xb9, 0xc9,
	0x24, 0xb6, 0x9b, 0xf9, 0xbd, 0x76, 0x56, 0x98,
	0xa3, 0xb2, 0x0f, 0x78, 0x5e, 0xcf, 0xd4, 0x2d,
	0x1e, 0xca, 0xef, 0xde, 0xea, 0x45, 0x55, 0x39,
	0xfd, 0x65, 0xff, 0xed, 0x89, 0xdd, 0xc4, 0x1e,
	0x60, 0x0d, 0x87, 0x8a, 0x77, 0x20, 0x01, 0x89,
	0x7d, 0x46, 0x0a, 0xa9, 0xb0, 0x87, 0x05, 0xfb,
	0x62, 0x00, 0xd9, 0xf7, 0x28, 0x75, 0x6a, 0x6f,
	0x99, 0xe1, 0x67, 0x4c, 0xa2, 0x87, 0xd5, 0x26,
	0xbc, 0x17, 0x64, 0x07, 0x84, 0x55, 0xc9, 0xd0,
	0xe2, 0x7f, 0x81, 0xae, 0xfc, 0x4d, 0xc1, 0x9a,
	0x1c, 0x7b, 0x18, 0x60, 0x8e, 0x03, 0x5b, 0x61,
	0x3f, 0x8a, 0xa5, 0xd1, 0x00, 0x47, 0x1d, 0x30,
}

var wbStaticPage1309Bytes280 = [...]byte{
	0x6b, 0xa9, 0x3f, 0x0a, 0xe5, 0x17, 0x53, 0x80,
	0xe2, 0xb0, 0x12, 0xa9, 0xdf, 0x89, 0x92, 0x51,
	0x13, 0x56, 0x22, 0x80,
}

var wbStaticPage1309Bytes2AD = [...]byte{
	0x56, 0x15, 0x72, 0x6d, 0xa6, 0x16, 0x92, 0x88,
	0x91, 0x23, 0x24, 0x09, 0x6c, 0xb5, 0x62, 0x50,
	0x8b, 0x24, 0x8d, 0x67, 0x26, 0xe8, 0x1f, 0x45,
	0xc9, 0x41,
}

var wbStaticPage1309Bytes2E0 = [...]byte{
	0xe3, 0x6f, 0xf9, 0x5e, 0xaa, 0xf4, 0x16, 0x1b,
	0xd5, 0x1a, 0xe4, 0x14, 0x45, 0x11, 0xff, 0x76,
	0xbb, 0x77, 0x07, 0xea, 0x96, 0x15, 0x84, 0x63,
	0x79, 0x8a,
}

var wbStaticPage1309Bytes314 = [...]byte{
	0x9e, 0xf0, 0x4a, 0xf5, 0x8f, 0xda, 0xe1, 0x02,
	0x2a, 0xe2, 0x96, 0xed, 0x9e, 0xc5, 0x01, 0x00,
	0x8b, 0xe4, 0x96, 0x19, 0x80, 0x83, 0x8c, 0x37,
	0x5a,
}

var wbStaticPage1309Bytes347 = [...]byte{
	0x05, 0x78, 0xe4, 0x23, 0x63, 0xde, 0x21, 0xd0,
	0x3b, 0xa1, 0xd4, 0x1c, 0x65, 0x79, 0x70, 0x3f,
	0x3d, 0x83, 0x5f, 0x2d, 0xda, 0x5a, 0xf6, 0x04,
	0x1d,
}

var wbStaticPage1309Bytes37A = [...]byte{
	0x7b, 0xbb, 0xee, 0xcc, 0xe8, 0x9f,
}

var wbStaticPage130CBytes5D0 = [...]byte{
	0x30, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes5D8 = [...]byte{
	0x34, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes5E0 = [...]byte{
	0x30, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes5E8 = [...]byte{
	0x88, 0x00, 0x00, 0x00, 0xdc, 0x04, 0x00, 0x00,
	0x3c, 0x01, 0x00, 0x00, 0x7c, 0x00, 0x00, 0x00,
	0x60, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes600 = [...]byte{
	0x80, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes60C = [...]byte{
	0x34, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes618 = [...]byte{
	0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes630 = [...]byte{
	0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes63C = [...]byte{
	0x3c, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xf4, 0x02, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x4c, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes654 = [...]byte{
	0x90, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytes66C = [...]byte{
	0x48, 0x01, 0x00, 0x00,
}

var wbStaticPage130CBytes678 = [...]byte{
	0xf5, 0x93, 0xa2, 0x42, 0x44, 0x67, 0x29, 0x83,
	0x70, 0xfc, 0x87, 0x96, 0xd1, 0x9d, 0x21, 0x9a,
	0x11,
}

var wbStaticPage130CBytes6B0 = [...]byte{
	0x49, 0x39, 0x8c, 0x1a, 0x38, 0xf0, 0xca, 0x3e,
	0x6d, 0x34, 0xb4, 0xb6, 0x35, 0x4f, 0x29, 0xd9,
	0xb9, 0x28, 0x27, 0x51,
}

var wbStaticPage130CBytes6DD = [...]byte{
	0x04, 0x32, 0x96, 0x4e, 0x9e, 0x7a, 0xb4, 0x93,
	0x5e, 0xe3, 0x18, 0x66, 0xf7, 0xdd, 0x6b, 0x81,
	0x99, 0x84, 0xef, 0x73, 0xef, 0xd0, 0x4b, 0x4a,
	0x7f, 0xef,
}

var wbStaticPage130CBytes710 = [...]byte{
	0x04, 0x9e, 0xbb, 0xbd, 0x9f, 0xe1, 0x22, 0xb6,
	0xb3, 0xdf, 0x7d, 0xe5, 0x91, 0xcc, 0x43, 0x45,
	0x68, 0xf5, 0x00, 0x22, 0x5c, 0xc1, 0x40, 0x82,
	0x39, 0x9e,
}

var wbStaticPage130CBytes744 = [...]byte{
	0x7c, 0xe2, 0x8d, 0x61, 0xee, 0x74, 0x27, 0x2f,
	0xde, 0xa2, 0xc8, 0x8e, 0x64, 0xb1, 0x32, 0x95,
	0x85, 0xe4, 0x52, 0x23, 0x48, 0xaa, 0xe6, 0x98,
	0x30,
}

var wbStaticPage130CBytes777 = [...]byte{
	0x58, 0xbf, 0xe3, 0x49, 0x61, 0x75, 0xf8, 0x55,
	0x63, 0xa7, 0x50, 0x8a, 0xc5, 0xce, 0xf0, 0x4d,
	0xb1, 0xb1, 0x6f, 0xfc, 0x44, 0xa8, 0x00, 0x90,
	0x82,
}

var wbStaticPage130CBytes7AA = [...]byte{
	0xa3, 0xdf, 0xdf, 0x71, 0x7c, 0xa0,
}

var wbStaticPage130CBytesBD8 = [...]byte{
	0x00, 0x00, 0x00, 0x00,
}

var wbStaticPage130CBytesBE8 = [...]byte{
	0x01, 0x00, 0x00, 0x00,
}

var wbStaticPage130CSpans = [...]struct {
	addr uint64
	data []byte
}{
	{addr: wbStaticPage130CBase + 0x5d0, data: wbStaticPage130CBytes5D0[:]},
	{addr: wbStaticPage130CBase + 0x5d8, data: wbStaticPage130CBytes5D8[:]},
	{addr: wbStaticPage130CBase + 0x5e0, data: wbStaticPage130CBytes5E0[:]},
	{addr: wbStaticPage130CBase + 0x5e8, data: wbStaticPage130CBytes5E8[:]},
	{addr: wbStaticPage130CBase + 0x600, data: wbStaticPage130CBytes600[:]},
	{addr: wbStaticPage130CBase + 0x60c, data: wbStaticPage130CBytes60C[:]},
	{addr: wbStaticPage130CBase + 0x618, data: wbStaticPage130CBytes618[:]},
	{addr: wbStaticPage130CBase + 0x630, data: wbStaticPage130CBytes630[:]},
	{addr: wbStaticPage130CBase + 0x63c, data: wbStaticPage130CBytes63C[:]},
	{addr: wbStaticPage130CBase + 0x654, data: wbStaticPage130CBytes654[:]},
	{addr: wbStaticPage130CBase + 0x66c, data: wbStaticPage130CBytes66C[:]},
	{addr: wbStaticPage130CBase + 0x678, data: wbStaticPage130CBytes678[:]},
	{addr: wbStaticPage130CBase + 0x6b0, data: wbStaticPage130CBytes6B0[:]},
	{addr: wbStaticPage130CBase + 0x6dd, data: wbStaticPage130CBytes6DD[:]},
	{addr: wbStaticPage130CBase + 0x710, data: wbStaticPage130CBytes710[:]},
	{addr: wbStaticPage130CBase + 0x744, data: wbStaticPage130CBytes744[:]},
	{addr: wbStaticPage130CBase + 0x777, data: wbStaticPage130CBytes777[:]},
	{addr: wbStaticPage130CBase + 0x7aa, data: wbStaticPage130CBytes7AA[:]},
	{addr: wbStaticPage130CBase + 0xbd8, data: wbStaticPage130CBytesBD8[:]},
	{addr: wbStaticPage130CBase + 0xbe8, data: wbStaticPage130CBytesBE8[:]},
}

var wbStaticPage1311Bytes174 = [...]byte{
	0x3c, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes180 = [...]byte{
	0x38, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes188 = [...]byte{
	0x40, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes190 = [...]byte{
	0x20, 0x03, 0x00, 0x00,
}

var wbStaticPage1311Bytes198 = [...]byte{
	0x34, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes1A0 = [...]byte{
	0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes704 = [...]byte{
	0x20, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes710 = [...]byte{
	0x78, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes718 = [...]byte{
	0x80, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes720 = [...]byte{
	0x58, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Bytes728 = [...]byte{
	0x9c, 0x00, 0x00, 0x00,
}

var wbStaticPage1311Spans = [...]struct {
	addr uint64
	data []byte
}{
	{addr: wbStaticPage1311Base + 0x174, data: wbStaticPage1311Bytes174[:]},
	{addr: wbStaticPage1311Base + 0x180, data: wbStaticPage1311Bytes180[:]},
	{addr: wbStaticPage1311Base + 0x188, data: wbStaticPage1311Bytes188[:]},
	{addr: wbStaticPage1311Base + 0x190, data: wbStaticPage1311Bytes190[:]},
	{addr: wbStaticPage1311Base + 0x198, data: wbStaticPage1311Bytes198[:]},
	{addr: wbStaticPage1311Base + 0x1a0, data: wbStaticPage1311Bytes1A0[:]},
	{addr: wbStaticPage1311Base + 0x704, data: wbStaticPage1311Bytes704[:]},
	{addr: wbStaticPage1311Base + 0x710, data: wbStaticPage1311Bytes710[:]},
	{addr: wbStaticPage1311Base + 0x718, data: wbStaticPage1311Bytes718[:]},
	{addr: wbStaticPage1311Base + 0x720, data: wbStaticPage1311Bytes720[:]},
	{addr: wbStaticPage1311Base + 0x728, data: wbStaticPage1311Bytes728[:]},
}

var wbStaticPage1314Bytes304 = [...]byte{
	0x80, 0x83, 0x00, 0x00, 0xda, 0x18, 0x00, 0x00,
}

var wbStaticPage1314Bytes318 = [...]byte{
	0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
}

var wbStaticPage1314Bytes334 = [...]byte{
	0x98, 0x01, 0x00, 0x00,
}

var wbStaticPage1314BytesF60 = [...]byte{
	0xe3, 0x41, 0x28, 0x51, 0xf2, 0xfd, 0xe7, 0x3f,
	0x98, 0xa1, 0x7f, 0xf4, 0xef, 0x0f, 0x30, 0x13,
	0x36,
}

var wbStaticPage1314Spans = [...]struct {
	addr uint64
	data []byte
}{
	{addr: wbStaticPage1314Base + 0x304, data: wbStaticPage1314Bytes304[:]},
	{addr: wbStaticPage1314Base + 0x318, data: wbStaticPage1314Bytes318[:]},
	{addr: wbStaticPage1314Base + 0x334, data: wbStaticPage1314Bytes334[:]},
	{addr: wbStaticPage1314Base + 0xf60, data: wbStaticPage1314BytesF60[:]},
}

var wbStaticPage130ABytes144 = [...]byte{
	0xaf, 0x4b, 0x93, 0x42, 0x06, 0xeb, 0xb2, 0x70,
	0x61, 0xca, 0xdf, 0xc3, 0x3a, 0x92, 0xa8, 0x49,
	0x75,
}

var wbStaticPage130ABytes830 = [...]byte{
	0x89, 0x9a, 0xa8, 0xc0, 0x5e, 0x09, 0x1c, 0xf9,
	0xe0, 0x9c, 0x3c, 0x62, 0x5a, 0x85, 0x52, 0x63,
	0x81, 0x7c, 0xc9, 0xf7, 0x7f, 0x97, 0x90, 0xf0,
	0x4f, 0x84, 0x44, 0x8a, 0xf5, 0x24, 0x09, 0x66,
	0xe3, 0x88, 0x80,
}

var wbStaticCopyByteRemainderTargets = [...]uint64{
	0x1a12d97ec, 0x1a12d97ec, 0x1a12d9720, 0x1a12d97ec,
	0x1a12d97ec, 0x1a12d97ec, 0x1a12d97ec,
}

var wbStaticCopyWordRemainderTargets = [...]uint64{
	0x1a12d9824, 0x1a12d9774, 0x1a12d9824, 0x1a12d9824,
	0x1a12d9824, 0x1a12d9824, 0x1a12d9824,
}

var wbStaticCopyFinalRemainderTargets = [...]uint64{
	0x1a12d97e8, 0x1a12d9840, 0x1a12d9840, 0x1a12d9840,
	0x1a12d9840, 0x1a12d9840, 0x1a12d9840, 0x1a12d9840,
}

var wbStaticPointerTable = [...]uint64{
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000001a1312af8,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000001a1314300,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x00000001a13125c8, 0x0000000000000000, 0x00000001a12a239f, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x00000001a12d0a36, 0x00000001a12a2a7f, 0x00000001b10b9bd2,
	0x0000000000000000, 0x00000001a130a86a, 0x0000000000000000, 0x00000001a130c6ba,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x00000001b10b9bbb, 0x00000001b10a3812, 0x00000001a1310dea, 0x00000001a12d6a7a,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000001a13075b6,
	0x0000000000000000, 0x00000001a12c48aa, 0x00000001a12d8f63, 0x0000000000000000,
	0x0000000000000000, 0x00000001a12cc13a, 0x0000000000000000, 0x00000001b10ba596,
	0x00000001b10b9be3, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x00000001a13120d8, 0x0000000000000000, 0x0000000000000000,
	0x00000001aeab6837, 0x0000000000000000, 0x0000000000000000, 0x00000001aeab6852,
	0x00000001a12d43fb, 0x0000000000000000, 0x00000001a12c66d3, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001a130e503, 0x0000000000000000,
	0x00000001a12cdaab, 0x00000001a12aed26, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x00000001a12d9626, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001a130e91f, 0x00000001a12d3582,
	0x00000001a12d60bb, 0x0000000000000000, 0x00000001a1309285, 0x00000001aeab68d2,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000001b10ae836,
	0x0000000000000000, 0x0000000000000000, 0x00000001a12cf83f, 0x0000000000000000,
	0x00000001a12cbdc7, 0x00000001a130a144, 0x00000001807d4787, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001b10b984b, 0x0000000000000000,
	0x0000000000000000, 0x00000001a130dd26, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001a12d3d9f, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x00000001a12bd34b, 0x0000000000000000, 0x00000001a130cbd3, 0x00000001a12ae2d6,
	0x00000001b10ae823, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x00000001a12d6d3a, 0x00000001a130c687, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x00000001a131029f, 0x00000001a1314f6e, 0x0000000000000000,
	0x00000001a130e951, 0x0000000000000000, 0x0000000000000000, 0x00000001a12d5d86,
	0x0000000000000000, 0x00000001a12b951a, 0x00000001806ed557, 0x0000000000000000,
	0x0000000000000000, 0x00000001a13129ea, 0x0000000000000000, 0x00000001b10b9bca,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001a12cf56b, 0x0000000000000000,
	0x00000001a12a61d3, 0x00000001a1312a37, 0x0000000000000000, 0x00000001a130c196,
	0x0000000000000000, 0x0000000000000000, 0x00000001a12c320f, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x00000001a130a830, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
}

func wbStaticPointerTableRead64(addr uint64) uint64 {
	return wbStaticPointerTable[int((addr-wbStaticPointerTableBase)>>3)]
}

func wbStaticVectorConstant(index int) [2]uint64 {
	return wbStaticVectorConstants[index]
}

func wbStaticSeedBranchTarget(base uint64, index uint64) uint64 {
	return uint64(int64(base) + int64(wbStaticSeedBranchOffsets[int(index)]))
}

func wbStaticEncodedWordCTarget(base uint64, index uint64) uint64 {
	return uint64(int64(base) + int64(wbStaticEncodedWordCOffsets[int(index)]))
}

func wbStaticPaddingZeroTarget(base uint64, index uint64) uint64 {
	return uint64(int64(base) + int64(wbStaticPaddingZeroOffsets[int(index)]))
}

func wbStaticPage130ERead32(addr uint64) uint32 {
	if v, ok := wbStaticPage130ERead32OK(addr); ok {
		return v
	}
	panic("unexpected static 0x1a130e000 read32")
}

func wbStaticPage130ERead32OK(addr uint64) (uint32, bool) {
	switch addr {
	case wbStaticPage130EBase + 0x2b4:
		return 0x0000003c, true
	case wbStaticPage130EBase + 0x500:
		return 0x03cd610a, true
	case wbStaticPage130EBase + 0x918:
		return 0x00000002, true
	case wbStaticPage130EBase + 0x928:
		return 0x00000002, true
	default:
		return 0, false
	}
}

func wbStaticPage130ERead32OrMem(mem *fpMem, addr uint64) uint32 {
	if v, ok := wbStaticPage130ERead32OK(addr); ok {
		return v
	}
	return mem.read32(addr)
}

func wbStaticPage130DRead32OK(addr uint64) (uint32, bool) {
	if addr == wbStaticPage130DBase+0x70c {
		return 0x0000002c, true
	}
	if addr < wbStaticPage130DBase+0xd20 {
		return 0, false
	}
	offset := addr - (wbStaticPage130DBase + 0xd20)
	if offset > uint64(len(wbStaticPage130DBytesD20)-4) {
		return 0, false
	}
	b := wbStaticPage130DBytesD20[offset:]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage130DRead64OK(addr uint64) (uint64, bool) {
	if addr < wbStaticPage130DBase+0xd20 {
		return 0, false
	}
	offset := addr - (wbStaticPage130DBase + 0xd20)
	if offset > uint64(len(wbStaticPage130DBytesD20)-8) {
		return 0, false
	}
	b := wbStaticPage130DBytesD20[offset:]
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, true
}

func wbStaticPage1309BytesAt(addr uint64, n int) ([]byte, bool) {
	if addr >= wbStaticPage1309Base+0x280 {
		offset := addr - (wbStaticPage1309Base + 0x280)
		if offset <= uint64(len(wbStaticPage1309Bytes280)-n) {
			return wbStaticPage1309Bytes280[int(offset):], true
		}
	}
	if addr >= wbStaticPage1309Base+0x2ad {
		offset := addr - (wbStaticPage1309Base + 0x2ad)
		if offset <= uint64(len(wbStaticPage1309Bytes2AD)-n) {
			return wbStaticPage1309Bytes2AD[int(offset):], true
		}
	}
	if addr >= wbStaticPage1309Base+0x2e0 {
		offset := addr - (wbStaticPage1309Base + 0x2e0)
		if offset <= uint64(len(wbStaticPage1309Bytes2E0)-n) {
			return wbStaticPage1309Bytes2E0[int(offset):], true
		}
	}
	if addr >= wbStaticPage1309Base+0x314 {
		offset := addr - (wbStaticPage1309Base + 0x314)
		if offset <= uint64(len(wbStaticPage1309Bytes314)-n) {
			return wbStaticPage1309Bytes314[int(offset):], true
		}
	}
	if addr >= wbStaticPage1309Base+0x347 {
		offset := addr - (wbStaticPage1309Base + 0x347)
		if offset <= uint64(len(wbStaticPage1309Bytes347)-n) {
			return wbStaticPage1309Bytes347[int(offset):], true
		}
	}
	if addr >= wbStaticPage1309Base+0x37a {
		offset := addr - (wbStaticPage1309Base + 0x37a)
		if offset <= uint64(len(wbStaticPage1309Bytes37A)-n) {
			return wbStaticPage1309Bytes37A[int(offset):], true
		}
	}
	return nil, false
}

func wbStaticPage1309Read8OK(addr uint64) (uint8, bool) {
	b, ok := wbStaticPage1309BytesAt(addr, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func wbStaticPage1309Read32OK(addr uint64) (uint32, bool) {
	switch addr {
	case wbStaticPage1309Base + 0x230:
		return 0x00003028, true
	case wbStaticPage1309Base + 0x238:
		return 0x00000064, true
	case wbStaticPage1309Base + 0x23c:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x244:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x248:
		return 0x00000074, true
	case wbStaticPage1309Base + 0x250:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x254:
		return 0x000000d0, true
	case wbStaticPage1309Base + 0x258:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x25c:
		return 0x00000078, true
	case wbStaticPage1309Base + 0x260:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x264:
		return 0x00000074, true
	case wbStaticPage1309Base + 0x268:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x26c:
		return 0x00000098, true
	case wbStaticPage1309Base + 0x274:
		return 0x00000000, true
	case wbStaticPage1309Base + 0x278:
		return 0x00000054, true
	}
	b, ok := wbStaticPage1309BytesAt(addr, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage130CBytesAt(addr uint64, n int) ([]byte, bool) {
	for _, span := range wbStaticPage130CSpans {
		if n > len(span.data) || addr < span.addr {
			continue
		}
		offset := addr - span.addr
		if offset <= uint64(len(span.data)-n) {
			return span.data[int(offset):], true
		}
	}
	return nil, false
}

func wbStaticPage130CRead8OK(addr uint64) (uint8, bool) {
	b, ok := wbStaticPage130CBytesAt(addr, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func wbStaticPage130CRead32OK(addr uint64) (uint32, bool) {
	b, ok := wbStaticPage130CBytesAt(addr, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage130CRead64OK(addr uint64) (uint64, bool) {
	b, ok := wbStaticPage130CBytesAt(addr, 8)
	if !ok {
		return 0, false
	}
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, true
}

func wbStaticPage1314BytesAt(addr uint64, n int) ([]byte, bool) {
	for _, span := range wbStaticPage1314Spans {
		if n > len(span.data) || addr < span.addr {
			continue
		}
		offset := addr - span.addr
		if offset <= uint64(len(span.data)-n) {
			return span.data[int(offset):], true
		}
	}
	return nil, false
}

func wbStaticPage1314Read8OK(addr uint64) (uint8, bool) {
	b, ok := wbStaticPage1314BytesAt(addr, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func wbStaticPage1314Read32OK(addr uint64) (uint32, bool) {
	b, ok := wbStaticPage1314BytesAt(addr, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage1314Read64OK(addr uint64) (uint64, bool) {
	b, ok := wbStaticPage1314BytesAt(addr, 8)
	if !ok {
		return 0, false
	}
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, true
}

func wbStaticPage1311BytesAt(addr uint64, n int) ([]byte, bool) {
	for _, span := range wbStaticPage1311Spans {
		if n > len(span.data) || addr < span.addr {
			continue
		}
		offset := addr - span.addr
		if offset <= uint64(len(span.data)-n) {
			return span.data[int(offset):], true
		}
	}
	return nil, false
}

func wbStaticPage1311Read8OK(addr uint64) (uint8, bool) {
	b, ok := wbStaticPage1311BytesAt(addr, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func wbStaticPage1311Read32OK(addr uint64) (uint32, bool) {
	b, ok := wbStaticPage1311BytesAt(addr, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage1311Read64OK(addr uint64) (uint64, bool) {
	b, ok := wbStaticPage1311BytesAt(addr, 8)
	if !ok {
		return 0, false
	}
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, true
}

func wbStaticPage130ABytesAt(addr uint64, n int) ([]byte, bool) {
	if addr >= wbStaticPage130ABase+0x144 {
		offset := addr - (wbStaticPage130ABase + 0x144)
		if offset <= uint64(len(wbStaticPage130ABytes144)-n) {
			return wbStaticPage130ABytes144[int(offset):], true
		}
	}
	if addr >= wbStaticPage130ABase+0x830 {
		offset := addr - (wbStaticPage130ABase + 0x830)
		if offset <= uint64(len(wbStaticPage130ABytes830)-n) {
			return wbStaticPage130ABytes830[int(offset):], true
		}
	}
	return nil, false
}

func wbStaticPage130ARead8OK(addr uint64) (uint8, bool) {
	b, ok := wbStaticPage130ABytesAt(addr, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func wbStaticPage130ARead32OK(addr uint64) (uint32, bool) {
	switch addr {
	case wbStaticPage130ABase + 0x890:
		return 0x00000000, true
	case wbStaticPage130ABase + 0x894:
		return 0x00000058, true
	case wbStaticPage130ABase + 0x8ac:
		return 0x00000198, true
	case wbStaticPage130ABase + 0xcd0:
		return 0x00000024, true
	case wbStaticPage130ABase + 0xe98:
		return 0x00000048, true
	}
	b, ok := wbStaticPage130ABytesAt(addr, 4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func wbStaticPage130ARead64OK(addr uint64) (uint64, bool) {
	if addr == wbStaticPage130ABase+0x890 {
		return 0x0000005800000000, true
	}
	b, ok := wbStaticPage130ABytesAt(addr, 8)
	if !ok {
		return 0, false
	}
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, true
}

func wbStaticPage130EReadS32(addr uint64) uint64 {
	return fpSignExtend(uint64(wbStaticPage130ERead32(addr)), 32)
}

func wbStaticPage130ERead8(addr uint64) uint8 {
	if v, ok := wbStaticPage130ERead8OK(addr); ok {
		return v
	}
	panic("unexpected static 0x1a130e000 read8")
}

func wbStaticPage130ERead8OK(addr uint64) (uint8, bool) {
	if addr < wbStaticPage130EBase+0x942 || addr >= wbStaticPage130EBase+0x942+uint64(len(wbStaticPage130EBytes942)) {
		return 0, false
	}
	return wbStaticPage130EBytes942[int(addr-(wbStaticPage130EBase+0x942))], true
}

func wbStaticPage130ERead8OrMem(mem *fpMem, addr uint64) uint8 {
	if v, ok := wbStaticPage130ERead8OK(addr); ok {
		return v
	}
	return mem.read8(addr)
}
