import java.math.BigInteger;
import java.util.Scanner;


public class RSACipher {

	public static void main(String[] args) {
		final Scanner s = new Scanner(System.in);
		final String N = s.nextLine();
		s.nextLine();
		final String f = s.nextLine();
		s.nextLine();
		final String m = s.nextLine();
		s.close();
		final Key k = new Key(new BigInteger(f), new BigInteger(N));
		System.out.println(k.cipher(m));
	}

}
