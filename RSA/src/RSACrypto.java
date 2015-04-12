import java.math.BigInteger;


public class RSACrypto {
	
	public static void main(String[] args) {
		final RSAKeyGenerator gen = new RSAKeyGenerator(1024);
		final Key[] K = gen.getK();
		
		final StringBuilder sb = new StringBuilder();
		final String lineSep = System.getProperty("line.separator");
		sb.append(bigIntToHex(K[0].n).getBytes().length);
		sb.append(lineSep);
		sb.append(lineSep);
		sb.append(bigIntToHex(K[0].f));
		sb.append(lineSep);
		sb.append(lineSep);
		sb.append(bigIntToHex(K[1].f));
		sb.append(lineSep);
		sb.append(lineSep);
		System.out.println(sb);
	}	
	
	private static String bigIntToHex(BigInteger bi) {
		final StringBuilder sb = new StringBuilder();
		final byte[] bytes = bi.toByteArray();
		System.out.println(bi.bitLength());
		for (byte b : bytes) {
			sb.append(Integer.toHexString(b));
		}
		long l = Integer.parseUnsignedInt(sb.toString());// b = new BigInteger(sb.toString(), 16);
		return sb.toString();
	}
}
