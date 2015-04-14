import java.math.BigInteger;
import java.util.Scanner;

public class RSACipher {
	//calls the given key's cipher function on the given message
	public static void main(String[] args) {
		final Scanner s = new Scanner(System.in);
		final BigInteger N = s.nextBigInteger(16);
		s.nextLine();
		final BigInteger f = s.nextBigInteger(16);
		s.nextLine();
		final BigInteger m = s.nextBigInteger(16);
		s.close();
		final Key k = new Key(f, N);
		System.out.println(k.cipher(m));
	}

}
