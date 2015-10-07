import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.io.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StraceAnalyzerBatch {

    private static int LINEFEED = 10;
    private static String SYSCALL_FUTEX = "futex";
    private static String SYSCALL_CLOCK = "clock_gettime";
    private static String SYSCALL_RESTART = "restart_syscall";
    private static String SYSCALL_MADVISE = "madvise";
    private static String SYSCALL_LSEEK = "lseek";
    private static String SYSCALL_FDATASYNC = "fdatasync";
    private static String SYSCALL_FCNTL = "fcntl";
    private static String SYSCALL_EPOLLWAIT = "epoll_wait";
    private static String SYSCALL_EPOLLCTL = "epoll_ctl";
    private static String SYSCALL_SOCKET = "socket";
    private static String SYSCALL_BIND = "bind";
    private static String SYSCALL_ECONNRESET = "ECONNRESET";
    private static String SYSCALL_ACCEPT = "accept";
    private static String SYSCALL_SETSOCKETOPT = "setsockopt";
    private static String SYSCALL_GETSOCKNAME = "getsockname";
    private static String SYSCALL_CONNECT = "connect";
    private static String SYSCALL_SELECT = " select";
    private static String SYSCALL_CLOSE = "close";
    private static String SYSCALL_RECVMSG = "recvmsg";
    private static String SYSCALL_SENDTO = "sendto";
    private static String SYSCALL_SHUTDOWN = "shutdown";
    private static String EAGAIN = "EAGAIN";
    private static String ETIMEDOUT = "ETIMEDOUT";
    private static String RESUME = "resumed";
    private static String UNFINISH = "unfinished";
    String outputDir = null;
    String straceLogName = null;
    String straceLogPath = null;
    String straceDirectoryPath = null;
    int fileNameIndex = 0;
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<String, List<SyscallEntry>> map = new HashMap<String, List<SyscallEntry>>();
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, List<SyscallEntry>> writevTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> recvfromTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, Set<SyscallEntry>> writeTbl = new HashMap<Integer, Set<SyscallEntry>>();
    HashMap<Integer, Set<SyscallEntry>> readTbl = new HashMap<Integer, Set<SyscallEntry>>();
    HashMap<Integer, Set<SyscallEntry>> lseekTbl = new HashMap<Integer, Set<SyscallEntry>>();
    HashMap<Integer, Set<SyscallEntry>> fsyncTbl = new HashMap<Integer, Set<SyscallEntry>>();
    HashMap<String, Set<SyscallEntry>> statTbl = new HashMap<String, Set<SyscallEntry>>();
    StringBuilder mdContent = new StringBuilder();
    StringBuilder topSyscallStr = new StringBuilder();
    SimpleDateFormat sdf = new SimpleDateFormat(
            "yyyy/MM/dd HH:mm:ss.SSS");
    File imgDir = null;


    public StraceAnalyzerBatch() {
        Properties prop = new Properties();
        FileInputStream file = null;

        String path = "src/config.properties";

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

        straceDirectoryPath = prop.getProperty("stracelogpath");
        if (!new File(straceDirectoryPath).exists() || !new File(straceDirectoryPath).isDirectory()) {
            System.err.format("strace log %s does not exist, or is not a directory since we are in batch mode\n", straceDirectoryPath);
            System.exit(-1);
        } else {
            System.err.format("reading strace log from directory: %s \n", straceDirectoryPath);
        }
        //straceLogName = new File(straceLogPath).getName();


    }

    public static void main(String[] args) {
        long begin = System.currentTimeMillis();

        StraceAnalyzerBatch sa = new StraceAnalyzerBatch();

        sa.batchAnalyze();


        System.err.format("\ntotal memory used %.2f M\n", (float) (Runtime
                .getRuntime().totalMemory() / (1024 * 1024)));
        System.err.format("\ntotal time spent %.0f Seconds \n",
                (float) ((System.currentTimeMillis() - begin) / 1000));

    }

    private void clear() {
        map = new HashMap<String, List<SyscallEntry>>();
        pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
        writevTbl = new HashMap<Integer, List<SyscallEntry>>();
        recvfromTbl = new HashMap<Integer, List<SyscallEntry>>();
        writeTbl = new HashMap<Integer, Set<SyscallEntry>>();
        readTbl = new HashMap<Integer, Set<SyscallEntry>>();
        lseekTbl = new HashMap<Integer, Set<SyscallEntry>>();
        fsyncTbl = new HashMap<Integer, Set<SyscallEntry>>();
        statTbl = new HashMap<String, Set<SyscallEntry>>();
        mdContent = new StringBuilder();
        topSyscallStr = new StringBuilder();

        sum_time = 0;
        fileNameIndex = 0;
    }

    private void batchAnalyze() {

        for (String currentLogFileName : new File(straceDirectoryPath).list()) {
            if (new File(straceLogPath, currentLogFileName).isDirectory())
                continue;
            else {
                straceLogName = currentLogFileName;
                straceLogPath = new File(straceDirectoryPath, currentLogFileName).getAbsolutePath();
                imgDir = new File(outputDir, currentLogFileName);
            }

            this.readFileNIO();
            this.calcDistribution();
            this.prettyPrint();

            this.createPlots();
            this.renderMarkdown();
            this.clear();
        }
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

        while ((line = readLineFromBuffer()) != null) {
            if (line.indexOf(SYSCALL_RESTART) != -1
                    || line.indexOf(SYSCALL_FUTEX) != -1
                    || line.indexOf(SYSCALL_MADVISE) != -1
                    || line.indexOf(SYSCALL_CLOCK) != -1
                    || line.indexOf(SYSCALL_EPOLLWAIT) != -1
                    || line.indexOf(SYSCALL_EPOLLCTL) != -1
                    || line.indexOf(SYSCALL_FCNTL) != -1
                    || line.indexOf(SYSCALL_SOCKET) != -1
                    || line.indexOf(SYSCALL_CONNECT) != -1
                    || line.indexOf(SYSCALL_GETSOCKNAME) != -1
                    || line.indexOf(SYSCALL_RECVMSG) != -1
                    || line.indexOf(SYSCALL_BIND) != -1
                    || line.indexOf(SYSCALL_ACCEPT) != -1
                    || line.indexOf(SYSCALL_SELECT) != -1
                    || line.indexOf(SYSCALL_CLOSE) != -1
                    || line.indexOf(SYSCALL_ECONNRESET) != -1
                    || line.indexOf(SYSCALL_SENDTO) != -1
                    || line.indexOf(SYSCALL_SHUTDOWN) != -1
                    || line.indexOf(SYSCALL_SETSOCKETOPT) != -1
                    || line.indexOf(EAGAIN) != -1
                    || line.indexOf(ETIMEDOUT) != -1)
                continue;

            SyscallEntry entry = new SyscallEntry();

            try {
                threadId = Integer
                        .parseInt(line.substring(0, line.indexOf(32)));

            } catch (Exception e) {
                System.err.println("ee " + line);
            }

            entry.setThreadId(threadId);

            Matcher m = pattern.matcher(line);
            if (m.find())
                syscall_index = m.start();// index of first non-digit character

            m.end();

            String call_time = line.split(" +")[1];
            call_time = call_time.substring(0, call_time.length() - 3);  // We can only parse time with millisecond resolution

            String start_time = "2014/05/02 " + call_time;

            try {
                entry.setCallTime(sdf.parse(start_time).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }

            if (line.contains(RESUME)) {// if the syscall says *** resumed, we
                // should match it to the previous
                // unfinished syscall -- matching via
                // thread ID
                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != 32) {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index,
                        syscall_end_index));

                if (entry.getSyscallName().equals("stat")) {

                    if (pendingSyscallTbl.containsKey(entry.getThreadId())) {

                        entry.setStatFileName(pendingSyscallTbl.get(
                                entry.getThreadId()).getStatFileName());
                        entry.setCallTime(pendingSyscallTbl.get(entry.getThreadId()).getCallTime());

                        pendingSyscallTbl.remove(entry.getThreadId());
                    } else {
                        System.err
                                .println("Cannot find the matching unfinished stat() syscall");
                    }
                }

                if (entry.getSyscallName().equals("write")
                        || entry.getSyscallName().equals("writev")
                        || entry.getSyscallName().equals("recvfrom")
                        || entry.getSyscallName().equals("read")
                        || entry.getSyscallName().equals("fdatasync")
                        || entry.getSyscallName().equals("lseek")) {

                    if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                        entry.setFd(pendingSyscallTbl.get(entry.getThreadId())
                                .getFd());
                        entry.setCallTime(pendingSyscallTbl.get(entry.getThreadId()).getCallTime());
                        pendingSyscallTbl.remove(entry.getThreadId());
                        // System.err.format("Matched resume with unfinished syscall, %s(%d \n",entry.getSyscallName(),entry.getFd());
                    } else {
                        System.err
                                .format("Cannot find the matching unfinished %s() syscall\n",
                                        entry.getSyscallName());
                        continue;
                    }
                }
            } else {
                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != '(') {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index,
                        syscall_end_index));

                if (entry.getSyscallName().equals("write")
                        || entry.getSyscallName().equals("read")
                        || entry.getSyscallName().equals("recvfrom")
                        || entry.getSyscallName().equals("writev")
                        || entry.getSyscallName().equals("lseek")) {

                    int syscall_fd_index = syscall_end_index;
                    while (line.charAt(syscall_fd_index) != ',') {
                        syscall_fd_index++;
                    }
                    int fd = Integer.valueOf(line.substring(
                            syscall_end_index + 1, syscall_fd_index));

                    entry.setFd(fd);

                }

                if (entry.getSyscallName().equals("fdatasync")) {

                    if (line.contains(UNFINISH)) {
                        int syscall_fd_index = syscall_end_index;
                        while (line.charAt(syscall_fd_index) != '<') {
                            syscall_fd_index++;
                        }
                        int fd = Integer.valueOf(line.substring(
                                syscall_end_index + 1, syscall_fd_index - 1));

                        entry.setFd(fd);
                    } else {
                        entry.setFd(Integer.valueOf(line.substring(syscall_end_index + 1, syscall_end_index + 2)));
                    }

                }

                if (entry.getSyscallName().equals("stat")) {

                    int stat_filename__index = syscall_end_index + 2;
                    while (line.charAt(stat_filename__index) != '"') {
                        stat_filename__index++;
                    }
                    String stat_file_name = line.substring(
                            syscall_end_index + 2, stat_filename__index);
                    entry.setStatFileName(stat_file_name);

                }

                if (line.contains(UNFINISH)) {
                    if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                        System.err
                                .format("Error: Unfinished system call already exist on the same thread %s \n",
                                        line);
                        System.err.format("The unfinished call is :\n", pendingSyscallTbl.get(entry.getThreadId()).toString());
                    } else {
                        pendingSyscallTbl.put(entry.getThreadId(), entry);
                    }
                    continue;
                }

            }

            float duration = Float.valueOf(line.substring(
                    line.lastIndexOf("<") + 1, line.lastIndexOf(">")));
            entry.setDuration(duration);

            if (entry.getSyscallName().equals("write")) {
                if (entry.getFd() <= 5)
                    continue;
                if (writeTbl.containsKey(entry.getFd())) {
                    writeTbl.get(entry.getFd()).add(entry);
                } else {
                    Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
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
                    Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
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
                    Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
                    l.add(entry);
                    lseekTbl.put(entry.getFd(), l);
                }
            }

            if (entry.getSyscallName().equals("fdatasync")) {
                if (entry.getFd() <= 5)
                    continue;
                if (fsyncTbl.containsKey(entry.getFd())) {
                    fsyncTbl.get(entry.getFd()).add(entry);
                } else {
                    Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
                    l.add(entry);
                    fsyncTbl.put(entry.getFd(), l);
                }

            }

            if (entry.getSyscallName().equals("stat")) {

                if (statTbl.containsKey(entry.getStatFileName())) {
                    statTbl.get(entry.getStatFileName()).add(entry);
                } else {
                    Set<SyscallEntry> l = new TreeSet<SyscallEntry>();
                    l.add(entry);
                    statTbl.put(entry.getStatFileName(), l);
                }
            }

            if (entry.getSyscallName().equals("recvfrom")
                    || entry.getSyscallName().equals("writev")) {
                int sz = Integer.valueOf(line.substring(
                        line.lastIndexOf("=") + 1, line.lastIndexOf("<"))
                        .trim());
                entry.setSize(sz);
            }

            if (entry.getSyscallName().equals("recvfrom")) {
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
        }

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

    private void createScatterPlot(HashMap<Integer, Set<SyscallEntry>> dataSource, String yAxisLabel, String fileSuffix) {
        for (Map.Entry<Integer, Set<SyscallEntry>> e : dataSource.entrySet()) {
            System.out.format("Number of %s in this FD %d: %d \n", yAxisLabel,
                    e.getKey(), e.getValue().size());
            JFreeChart chart = ChartFactory.createTimeSeriesChart("FD:" + e.getKey() + yAxisLabel + "() response time", "time", "Response Time in Millisecond", createDataset(e.getValue()));
            XYPlot plot = (XYPlot) chart.getPlot();
            DateAxis axis = (DateAxis) plot.getDomainAxis();
            axis.setDateFormatOverride(new SimpleDateFormat("HH:mm:ss"));
            try {

                if (!imgDir.exists())
                    imgDir.mkdirs();

                String imgFileName = fileNameIndex++ + fileSuffix;
                ChartUtilities.saveChartAsJPEG(new File(imgDir, imgFileName), chart, 1024,
                        768, null);
                mdContent.append(String.format(MarkdownTags.IMAGE, imgFileName, straceLogName + "/" + imgFileName));
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }
    }

    private XYDataset createDataset(Set<SyscallEntry> calls) {
        TimeSeriesCollection result = new TimeSeriesCollection();
        TimeSeries series = new TimeSeries("");

        for (SyscallEntry callEntry : calls) {
            series.addOrUpdate(new Millisecond(new Date(callEntry.getCallTime())),
                    callEntry.getDuration() * 1000);
        }
        result.addSeries(series);
        return result;
    }

    /**
     * not used for now as we output TimeSeries plot, in case of switching to scatter plot we can use this method to provide dataset
     */
    private XYDataset createDatasetNumberDomain(Set<SyscallEntry> calls) {
        XYSeriesCollection result = new XYSeriesCollection();
        XYSeries series = new XYSeries("");
        int count = 0;
        double base = 0;
        for (SyscallEntry callEntry : calls) {
            if (count == 0) {
                base = callEntry.getCallTime();
                series.add(0, callEntry.getDuration());
            } else
                series.add(callEntry.getCallTime() - base,
                        callEntry.getDuration() * 1000);
            count++;
        }
        result.addSeries(series);
        return result;
    }

    private void createScatterPlotStat() {

        for (Map.Entry<String, Set<SyscallEntry>> e : statTbl.entrySet()) {
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
                mdContent.append(String.format(MarkdownTags.IMAGE, imgFileName, straceLogName + "/" + imgFileName));
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
