import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TrussAnalyzer {

    private static int LINEFEED = 10;
    private static String SYSCALL_CLOCK = "time";
    private static String SYSCALL_GETPID = "getpid";
    private static String SYSCALL_FDATASYNC = "fsync";
    private static String SYSCALL_PARK = "lwp_park";
    private static String SYSCALL_UNPARK = "lwp_unpark";
    private static String SYSCALL_IOCTL = "ioctl";
    private static String SYSCALL_FCNTL = "fcntl";
    private static String SYSCALL_SOCKET = "socket";
    private static String SYSCALL_BIND = "bind";
    private static String SYSCALL_ECONNRESET = "ECONNRESET";
    private static String SYSCALL_FTRUNCATE = "ftruncate";
    private static String SYSCALL_ACCEPT = "accept";
    private static String SYSCALL_SETSOCKETOPT = "setsockopt";
    private static String SYSCALL_GETSOCKNAME = "getsockname";
    private static String SYSCALL_CONNECT = "connect";
    private static String SYSCALL_CLOSE = "close";
    private static String SYSCALL_SHUTDOWN = "shutdown";
    private static String SIGNAL = "SIG";
    private static String UNFINISH = "sleeping";
    private static String EPIPE = "EPIPE";
    private static String EAGAIN = "EAGAIN";
    String outputDir = null;
    String straceLogName = null;
    String straceLogPath = null;
    int fileNameIndex = 0;
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<String, List<SyscallEntry>> map = new HashMap<String, List<SyscallEntry>>();
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, List<SyscallEntry>> writevTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> recvfromTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> writeTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> readTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> lseekTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> fsyncTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<String, List<SyscallEntry>> statTbl = new HashMap<String, List<SyscallEntry>>();
    StringBuilder mdContent = new StringBuilder();
    StringBuilder topSyscallStr = new StringBuilder();
    SimpleDateFormat sdf = new SimpleDateFormat(
            "yyyy/MM/dd HH:mm:ss.SSS");
    File imgDir = null;

    public TrussAnalyzer() {
        Properties prop = new Properties();
        FileInputStream file = null;

        String path = "./truss-config.properties";

        try {
            file = new FileInputStream(path);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            prop.load(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
        assert file != null;
        try {
            file.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        outputDir = prop.getProperty("outputdir");
        if (!new File(outputDir).exists()) {
            System.err.format("File Directory %s does not exist\n", outputDir);
            System.exit(-1);
        } else {
            System.err.format("Report will be created in %s \n", outputDir);
        }

        straceLogPath = prop.getProperty("stracelogpath");
        if (!new File(straceLogPath).exists()) {
            System.err.format("strace log %s does not exist\n", straceLogName);
            System.exit(-1);
        } else {
            System.err.format("reading strace log from %s \n", straceLogPath);
        }
        straceLogName = new File(straceLogPath).getName();

        imgDir = new File(outputDir, straceLogName);
    }

    public static void main(String[] args) {
        long begin = System.currentTimeMillis();
        TrussAnalyzer sa = new TrussAnalyzer();

        sa.readFileNIO();
        sa.calcDistribution();
        sa.prettyPrint();

        sa.createPlots();
        sa.renderMarkdown();

        System.err.format("\ntotal memory used %.2f M\n", (float) (Runtime
                .getRuntime().totalMemory() / (1024 * 1024)));
        System.err.format("\ntotal time spent %.0f Seconds \n",
                (float) ((System.currentTimeMillis() - begin) / 1000));

    }

    private void createPlots() {
        createScatterPlot(writeTbl, " write", "_write.jpg");
        createScatterPlot(readTbl, " read", "_read.jpg");
        createScatterPlot(fsyncTbl, " fdatasync", "_fdatasync.jpg");
        createScatterPlot(lseekTbl, " lseek", "_lseek.jpg");
        createScatterPlotStat();
    }

    private void readFileNIO() {
        File f = new File(straceLogPath);

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

        int lineNo = 0;

        int syscall_endindex = 0;
        while ((line = readLineFromBuffer()) != null) {


            if (line.indexOf(SYSCALL_CLOCK) != -1
                    || line.indexOf(SYSCALL_GETPID) != -1
                    || line.indexOf(SYSCALL_FTRUNCATE) != -1
                    || line.indexOf(SYSCALL_PARK) != -1
                    || line.indexOf(SYSCALL_UNPARK) != -1
                    || line.indexOf(SYSCALL_IOCTL) != -1
                    || line.indexOf(SYSCALL_FCNTL) != -1
                    || line.indexOf(SYSCALL_SOCKET) != -1
                    || line.indexOf(SYSCALL_CONNECT) != -1
                    || line.indexOf(SYSCALL_GETSOCKNAME) != -1
                    || line.indexOf(SYSCALL_BIND) != -1
                    || line.indexOf(SYSCALL_ACCEPT) != -1
                    || line.indexOf(SYSCALL_CLOSE) != -1
                    || line.indexOf(SYSCALL_ECONNRESET) != -1
                    || line.indexOf(SYSCALL_SHUTDOWN) != -1
                    || line.indexOf(SYSCALL_SETSOCKETOPT) != -1
                    || line.indexOf(UNFINISH) != -1
                    || line.indexOf(SIGNAL) != -1
                    || line.indexOf(EPIPE) != -1
                    || line.indexOf(EAGAIN) != -1
                    )
                continue;

            SyscallEntry entry = new SyscallEntry();

            try {
                threadId = Integer.parseInt(line.substring(0, line.indexOf(":")).split("/")[1]);
            } catch (Exception ee) {
                System.err.println("ee " + line);
            }

            entry.setThreadId(threadId);

            Matcher m = pattern.matcher(line);
            if (m.find())
                syscall_index = m.start();// index of first non-digit character

            m.end();

            syscall_endindex = line.indexOf("(");


            entry.setSyscallName(line.substring(syscall_index, syscall_endindex));


            if (entry.getSyscallName().equals("write")
                    || entry.getSyscallName().equals("read")
                    || entry.getSyscallName().equals("recv")
                    || entry.getSyscallName().equals("writev")
                    || entry.getSyscallName().equals("lseek")) {
                entry.setFd(Integer.valueOf(line.substring(syscall_endindex + 1, line.indexOf(","))));
            }


            if (entry.getSyscallName().equals("stat")) {

                int stat_filename__index = syscall_endindex + 2;
                while (line.charAt(stat_filename__index) != '"') {
                    stat_filename__index++;
                }
                String stat_file_name = line.substring(
                        syscall_endindex + 2, stat_filename__index);
                entry.setStatFileName(stat_file_name);

            }

            float duration = Float.valueOf(line.substring(syscall_index - 8, syscall_index).trim());
            entry.setDuration(duration);


            if (entry.getSyscallName().equals("write")) {
                if (entry.getFd() <= 5)
                    continue;
                if (writeTbl.containsKey(entry.getFd())) {
                    writeTbl.get(entry.getFd()).add(entry);
                } else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    writeTbl.put(entry.getFd(), l);
                }
            }
            if (entry.getSyscallName().equals("read")) {
                if (entry.getFd() <= 5)
                    continue;
                if (readTbl.containsKey(entry.getFd())) {
                    readTbl.get(entry.getFd()).add(entry);
                } else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    readTbl.put(entry.getFd(), l);
                }
            }

            if (entry.getSyscallName().equals("lseek")) {
                if (entry.getFd() <= 5)
                    continue;
                if (lseekTbl.containsKey(entry.getFd())) {
                    lseekTbl.get(entry.getFd()).add(entry);
                } else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    lseekTbl.put(entry.getFd(), l);
                }
            }

            if (entry.getSyscallName().equals("fdsync")) {
                if (entry.getFd() <= 5)
                    continue;
                if (fsyncTbl.containsKey(entry.getFd())) {
                    fsyncTbl.get(entry.getFd()).add(entry);
                } else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    fsyncTbl.put(entry.getFd(), l);
                }

            }

            if (entry.getSyscallName().equals("stat")) {

                if (statTbl.containsKey(entry.getStatFileName())) {
                    statTbl.get(entry.getStatFileName()).add(entry);
                } else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    statTbl.put(entry.getStatFileName(), l);
                }
            }

            if (entry.getSyscallName().equals("recv")
                    || entry.getSyscallName().equals("writev")) {
                int sz = Integer.valueOf(line.substring(line.lastIndexOf("=") + 1).trim());
                entry.setSize(sz);
            }

            if (entry.getSyscallName().equals("recv")) {
                if (recvfromTbl.containsKey(entry.getFd()))
                    recvfromTbl.get(entry.getFd()).add(entry);
                else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    recvfromTbl.put(entry.getFd(), l);
                }
            }

            if (entry.getSyscallName().equals("writev")) {
                if (writevTbl.containsKey(entry.getFd()))
                    writevTbl.get(entry.getFd()).add(entry);
                else {
                    List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                    l.add(entry);
                    writevTbl.put(entry.getFd(), l);
                }
            }

            sum_time += duration;

            if (map.containsKey(entry.getSyscallName())) {
                map.get(entry.getSyscallName()).add(entry);
            } else {
                List<SyscallEntry> l = new ArrayList<SyscallEntry>();
                l.add(entry);
                map.put(entry.getSyscallName(), l);
            }

            lineNo++;
        }

        System.out.format("Total line read: %d %n", lineNo);
    }

    /**
     * We print the following information:
     * - System call distribution by syscall names and time usage percentage
     * - Top 10 time consuming syscall grouped by each system call name
     * - Top 10 read/write total size of recvfrom()/writev() syscall, this typically can pinpoint the file descriptor which are generating traffic, it can then be used together with lsof output to find out the client IP address
     */
    private void prettyPrint() {

        String time = "% time";
        String seconds = "seconds";
        String calls = "calls";
        String syscall = "syscall";


        mdContent.append(String.format("%s%6s %11s %9s %16s\n", MarkdownTags.CODEBLOCK, time, seconds, calls, syscall));

        mdContent.append(String.format("%s------ ----------- --------- ----------------\n", MarkdownTags.CODEBLOCK));

        float time_percent = 0;
        int count_per_syscall = 0;
        for (Map.Entry<String, List<SyscallEntry>> e : map.entrySet()) {
            float total_time_syscall = 0;
            for (SyscallEntry call : e.getValue()) {
                total_time_syscall += call.getDuration();
            }
            time_percent = 100 * total_time_syscall / sum_time;
            count_per_syscall = e.getValue().size();
            mdContent.append(String.format("%s%5.2f %12.2f %9d %16s\n", MarkdownTags.CODEBLOCK, time_percent, total_time_syscall, count_per_syscall, e.getKey()));

            sort(e.getValue());
            for (int i = 0; i < (e.getValue().size() < 10 ? e.getValue().size() : 10); i++) {
                topSyscallStr.append(String.format("%s%s---%.7f  \n", MarkdownTags.QUOTE, e.getKey(), e.getValue().get(i).getDuration()));
            }

            topSyscallStr.append("\n\n");
        }


        mdContent.append(String.format(" \n\n### FDs that send the most traffic to EMS \n\n"));
        List<ReadWriteSizeContainer> rwSet = new LinkedList<ReadWriteSizeContainer>();
        for (Map.Entry<Integer, List<SyscallEntry>> e : recvfromTbl.entrySet()) {
            int total_size = 0;
            for (SyscallEntry se : e.getValue()) {
                total_size += se.getSize();
            }

            rwSet.add(new ReadWriteSizeContainer(e.getKey(), total_size));

        }

        int show = 10;
        Collections.sort(rwSet);
        Iterator<ReadWriteSizeContainer> ite = rwSet.iterator();
        while (ite.hasNext() && show-- > 0) {
            mdContent.append(String.format("%s%s\n", MarkdownTags.CODEBLOCK, ite.next()));
        }


        mdContent.append(String.format(" \n\n### FDs that get the most traffic from EMS \n\n"));
        List<ReadWriteSizeContainer> rwSet2 = new LinkedList<ReadWriteSizeContainer>();
        for (Map.Entry<Integer, List<SyscallEntry>> e : writevTbl.entrySet()) {
            int total_size = 0;
            for (SyscallEntry se : e.getValue()) {
                total_size += se.getSize();
            }

            rwSet2.add(new ReadWriteSizeContainer(e.getKey(), total_size));

        }

        Collections.sort(rwSet2);
        ite = rwSet2.iterator();

        show = 10;
        while (ite.hasNext() && show-- > 0) {
            mdContent.append(String.format("%s%s\n", MarkdownTags.CODEBLOCK, ite.next()));
        }

        mdContent.append(" \n\n Syscall response time top 10 \n\n");
        mdContent.append(topSyscallStr);

        mdContent.append("```\n The following sections try to illustrate in a graph of how the VFS system call performs, \n those calls are typically sources of slow. " +
                " The targets are the datastore files used by EMS including \n" +
                " async-msgs.db | sync-msgs.db | meta.db \n" +
                " From strace it is not possible to find the exact file name, \n one have to run lsof -p <pid> | grep db to find out which fd corresponds to which file \n```\n");

    }

    private void renderMarkdown() {
        try {
            File markDownFile = new File(outputDir, straceLogName + ".md");
            System.err.format("The report is created -- %s \n", markDownFile.getAbsolutePath());
            BufferedWriter bw = new BufferedWriter(new FileWriter(markDownFile));
            bw.write(mdContent.toString());
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createScatterPlot(HashMap<Integer, List<SyscallEntry>> dataSource, String yAxisLabel, String fileSuffix) {


        for (Map.Entry<Integer, List<SyscallEntry>> e : dataSource.entrySet()) {
            System.out.format("Number of %s in this FD %d: %d \n", yAxisLabel,
                    e.getKey(), e.getValue().size());
            //JFreeChart chart = ChartFactory.createTimeSeriesChart("FD:" + e.getKey() + yAxisLabel + "() response time", "time", "Response Time in Millisecond", createDataset(e.getValue()));

            JFreeChart chart = ChartFactory.createScatterPlot(
                    "FD:" + e.getKey() + yAxisLabel + "() response time", // chart title
                    "X", // x axis label
                    "Response Time in millisecond", // y axis label
                    createDataset(e.getValue()), // data  ***-----PROBLEM------***
                    PlotOrientation.VERTICAL,
                    true, // include legend
                    true, // tooltips
                    false // urls
            );

            try {

                if (imgDir.exists()) {
                    imgDir = new File(outputDir, straceLogName + "a");
                    imgDir.mkdirs();
                }
                String imgFileName = fileNameIndex++ + fileSuffix;
                ChartUtilities.saveChartAsJPEG(new File(imgDir, imgFileName), chart, 1024,
                        768, null);
                mdContent.append(String.format(MarkdownTags.IMAGE, imgFileName, imgDir.getAbsolutePath() + "/" + imgFileName));
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }
    }

    private XYDataset createDataset(List<SyscallEntry> calls) {
        XYSeriesCollection result = new XYSeriesCollection();
        XYSeries series = new XYSeries("Response Time");
        int count = 0;
        double base = 1;
        for (SyscallEntry callEntry : calls) {
            series.add(count++, callEntry.getDuration() * 1000);
        }
        result.addSeries(series);
        return result;
    }


    private void createScatterPlotStat() {

        for (Map.Entry<String, List<SyscallEntry>> e : statTbl.entrySet()) {
            JFreeChart chart = ChartFactory.createTimeSeriesChart(e.getKey() + " stat() response time", "time", "Response time in Millisecond", createDataset(e.getValue()));

            // create and display a frame...
            /*
             * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */
            try {


                String imgFileName = fileNameIndex++ + "_stat.jpg";
                ChartUtilities.saveChartAsJPEG(new File(imgDir, imgFileName), chart, 1024,
                        768, null);
                mdContent.append(String.format(MarkdownTags.IMAGE, imgFileName, imgDir.getAbsolutePath() + "/" + imgFileName));
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }
    }

    private void sort(List<SyscallEntry> syscallCollections) {
        Collections.sort(syscallCollections);

    }
}
