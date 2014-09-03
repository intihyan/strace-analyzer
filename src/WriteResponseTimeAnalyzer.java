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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Created with IntelliJ IDEA.
 * User: yanlinfeng
 * Date: 7/15/14
 * Time: 10:39 AM
 * To change this template use File | Settings | File Templates.
 */
public class WriteResponseTimeAnalyzer {

    private static int LINEFEED = 10;
    private static String SYSCALL_FUTEX = "futex";
    private static String SYSCALL_CLOCK = "clock_gettime";
    private static String RESUME = "resumed";
    private static String UNFINISH = "unfinished";
    String fileName = "/Users/yanlinfeng/strace.log";
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, Set<SyscallEntry>> writeTbl = new HashMap<Integer,Set<SyscallEntry>>();

    public static void main(String[] args) {
        long begin = System.currentTimeMillis();
        WriteResponseTimeAnalyzer sa = new WriteResponseTimeAnalyzer();

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

        String regex = "[A-z]";
        Pattern pattern = Pattern.compile(regex);

        int threadId = 0;
        while ((line = readLineFromBuffer()) != null) {


            SyscallEntry entry = new SyscallEntry();
            String syscallName;

            try {
                threadId = Integer.parseInt(line.substring(0, line.indexOf(32)));

            } catch (Exception e) {
                System.err.println("ee " + line);
            }

            entry.setThreadId(threadId);

            Matcher m = pattern.matcher(line);
            if (m.find())
                syscall_index = m.start();// index of first non-digit character

            m.end();

            String temp = line.substring(line.indexOf(32), syscall_index).trim();
            temp = temp.substring(0,temp.length()-3);
            String start_time = "2014/05/02 " + temp;
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSSSSS");
            try {
                entry.setCallTime(sdf.parse(start_time).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }

            if (!(line.contains(RESUME))) {

                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != '(') {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index, syscall_end_index));

                if (entry.getSyscallName().equals("write")) {

                    int syscall_size_index = syscall_end_index;
                    while (line.charAt(syscall_size_index) != ',') {
                        syscall_size_index++;
                    }
                    int fd = Integer.valueOf(line.substring(syscall_end_index + 1, syscall_size_index));
                    if (fd > 5)
                        entry.setFd(fd);
                    else
                        continue;


                    if (line.contains(UNFINISH)) {
                        if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                            System.err.println("Error");
                        } else {
                            pendingSyscallTbl.put(entry.getThreadId(), entry);
                        }
                    }
                }
                else
                    continue;

            } else { // if the syscall says *** resumed, we should match it to the previous unfinished syscall -- matching via thread ID

                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != 32) {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index, syscall_end_index));
                if (!entry.getSyscallName().equals("write")) {
                    continue;
                }
                if (entry.getFd() <= 5)
                    continue;
                if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                    entry.setFd(pendingSyscallTbl.get(entry.getThreadId()).getFd());
                    pendingSyscallTbl.remove(entry.getThreadId());
                    //System.err.format("Matched resume with unfinished syscall, fd %s size %d\n",entry.getFd(),entry.getSize());
                } else {
                    System.err.println("Cannot find the matching unfinished syscall");
                }
            }

            if (line.contains(UNFINISH))
                continue;

            float duration = Float.valueOf(line.substring(line.lastIndexOf("<") + 1, line.lastIndexOf(">")));
            entry.setDuration(duration);


            if(entry.getFd() == 0)
                System.err.println(line);
            if (writeTbl.containsKey(entry.getFd())) {
                writeTbl.get(entry.getFd()).add(entry);
            } else {
                Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
                l.add(entry);
                writeTbl.put(entry.getFd(), l);
            }
        }


    }

    private XYDataset createDataset(Set<SyscallEntry> calls) {
        XYSeriesCollection result = new XYSeriesCollection();
        XYSeries series = new XYSeries("Random");
        int count = 0;
        double base = 0;
        for (SyscallEntry callEntry : calls) {
            if(count == 0){
               base = callEntry.getCallTime();
                System.err.format("%f \n",base);
               series.add(0, callEntry.getDuration());
            }
            else
                series.add(callEntry.getCallTime() - base, callEntry.getDuration());
            count++;
        }
        result.addSeries(series);
        return result;
    }

    private void createScatterPlot() {

        for (Map.Entry<Integer, Set<SyscallEntry>> e : writeTbl.entrySet()) {
            JFreeChart chart = ChartFactory.createScatterPlot(
                    "Scatter Plot", // chart title
                    "X", // x axis label
                    "Y", // y axis label
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
        }
    }

    private void sort(List<SyscallEntry> syscallCollections) {
        Collections.sort(syscallCollections);

    }
}

