import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class WriteResponseTimeAnalyzer_Truss {

    private static int LINEFEED = 10;
    private static String SYSCALL_FUTEX = "futex";
    private static String SYSCALL_CLOCK = "clock_gettime";
    private static String RESUME = "resumed";
    private static String UNFINISH = "unfinished";
    String fileName = "/Users/yanlinfeng/Dropbox/test/write.truss.log";
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, List<SyscallEntry>> writeTbl = new HashMap<Integer, List<SyscallEntry>>();

    public static void main(String[] args) {
        long begin = System.currentTimeMillis();
        WriteResponseTimeAnalyzer_Truss sa = new WriteResponseTimeAnalyzer_Truss();

        sa.readFileNIO();
        sa.calcDistribution();
        sa.createScatterPlot();
        System.err.format("\ntotal memory used %.2f M\n", (float) (Runtime.getRuntime().totalMemory() / (1024 * 1024)));

        System.err.format("\ntotal time spent %.0f Seconds", (float) ((System.currentTimeMillis() - begin) / 1000));
    }

    private void readFileNIO() {
        File f = new File(fileName);

        try {
            FileChannel fc = new RandomAccessFile(f, "rw").getChannel();
            buffer = fc.map(FileChannel.MapMode.READ_WRITE, 0, fc.size());

            buffer.load();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private String readLineFromBuffer() {
        byte[] b = new byte[1024];
        int index = 0;
        while (buffer.position() < buffer.limit()) {
            b[index] = buffer.get();
            if (b[index] == LINEFEED)
                break;
            if (index++ >= 1023) {
                byte[] large_byte = new byte[20480];
                System.arraycopy(b, 0, large_byte, 0, b.length);
                b = large_byte;
            }
        }

        if (buffer.position() == buffer.limit())
            return null;

        byte[] temp = new byte[index];

        System.arraycopy(b, 0, temp, 0, index);
        return new String(temp);
    }

    private void calcDistribution() {
        String line;
        int syscall_index = 0;
        int syscall_endindex = 0;
        String regex = "[A-z]";
        Pattern pattern = Pattern.compile(regex);

        int threadId = 0;
        while ((line = readLineFromBuffer()) != null) {


            SyscallEntry entry = new SyscallEntry();
            String syscallName;

            try {
                threadId = Integer.parseInt(line.substring(0, line.indexOf(":")).split("/")[1]);
            } catch (Exception e) {
                System.err.println("ee " + line);
            }

            entry.setThreadId(threadId);

            Matcher m = pattern.matcher(line);
            if (m.find())
                syscall_index = m.start();// index of first non-digit character

            m.end();

            syscall_endindex = line.indexOf("(");
            entry.setSyscallName(line.substring(syscall_index, syscall_endindex));

            if (entry.getSyscallName() != null && !entry.getSyscallName().equals("write"))
                continue;

            entry.setFd( Integer.valueOf(line.substring(syscall_endindex + 1, line.indexOf(",")))) ;

            if (entry.getFd() < 6)
                continue;

            if (line.contains("sleeping"))
                continue;

            entry.setDuration(Float.valueOf(line.substring(syscall_index - 8, syscall_index).trim()));

            if (writeTbl.containsKey(entry.getFd())) {
                writeTbl.get(entry.getFd()).add(entry);
            } else {
                List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                l.add(entry);
                writeTbl.put(entry.getFd(), l);
            }
        }


    }

    private XYDataset createDataset(List<SyscallEntry> calls) {
        XYSeriesCollection result = new XYSeriesCollection();
        XYSeries series = new XYSeries("Random");
        int count = 0;
        double base = 1;
        for (SyscallEntry callEntry : calls) {
            series.add(count++, callEntry.getDuration() * 1000);
        }
        result.addSeries(series);
        return result;
    }

    private void createScatterPlot() {
        double total_time = 0.0;
        for (Map.Entry<Integer, List<SyscallEntry>> e : writeTbl.entrySet()) {
            total_time = 0.0;
            JFreeChart chart = ChartFactory.createScatterPlot(
                    "write() response time", // chart title
                    "X", // x axis label
                    "Response Time in millisecond", // y axis label
                    createDataset(e.getValue()), // data  ***-----PROBLEM------***
                    PlotOrientation.VERTICAL,
                    true, // include legend
                    true, // tooltips
                    false // urls
            );

            // create and display a frame...
            ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
            frame.pack();
            frame.setVisible(true);


            for (SyscallEntry s : e.getValue()) {
                total_time += s.getDuration();
            }
            System.err.format(" average write response time for file descriptor %d is %f ", e.getKey(), total_time / e.getValue().size());
            System.err.format(" total time spent %f  total calls %d \n", total_time, e.getValue().size() );

        }
    }


}

