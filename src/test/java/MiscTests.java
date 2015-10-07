import org.junit.Test;

/**
 * Created with IntelliJ IDEA.
 * User: yanlinfeng
 * Date: 1/12/15
 * Time: 5:02 PM
 * To change this template use File | Settings | File Templates.
 */
public class MiscTests {

    @Test
    public void testBitwise(){
        long param = 5511;
        long p1, p2 ;
        p1  = param | 32768L;
        p2 = p1 >>> 8;
        System.out.format("%d \n", p1);
        System.out.format("%d \n", p2);
        System.out.format("%d \n", (byte)(int)p1);

        System.out.format("Length of sessid:  %d \n", "sessid".length()) ;

        System.out.format("%d \n", (byte)(int)7);
    }
}
