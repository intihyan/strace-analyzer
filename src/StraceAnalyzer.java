import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class StraceAnalyzer {

    private static int LINEFEED = 10;
    private static String SYSCALL_FUTEX = "futex";
    private static String SYSCALL_CLOCK = "clock_gettime";
    private static String RESUME = "resumed";
    private static String UNFINISH = "unfinished";
    String fileName = "/Users/yanlinfeng/strace.log";
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<String, List<SyscallEntry>> map = new HashMap<String, List<SyscallEntry>>();
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, List<SyscallEntry>> writevTbl = new HashMap<Integer, List<SyscallEntry>>();
    HashMap<Integer, List<SyscallEntry>> recvfromTbl = new HashMap<Integer, List<SyscallEntry>>();

    public static void main(String[] args) {
        long begin = System.currentTimeMillis();
        StraceAnalyzer sa = new StraceAnalyzer();

        sa.readFileNIO();
        sa.calcDistribution();
        sa.prettyPrint();

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

            if (!(line.contains(RESUME))) {
                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != '(') {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index, syscall_end_index));


                if (entry.getSyscallName().equals("recvfrom") || entry.getSyscallName().equals("writev")) {
                    int syscall_size_index = syscall_end_index;
                    while (line.charAt(syscall_size_index) != ',') {
                        syscall_size_index++;
                    }
                    entry.setFd(Integer.valueOf(line.substring(syscall_end_index + 1, syscall_size_index)));


                    if (line.contains(UNFINISH)) {
                        if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                            System.err.println("Error");
                        } else {
                            pendingSyscallTbl.put(entry.getThreadId(), entry);
                        }
                    } else {
                        int temp = Integer.valueOf(line.substring(line.lastIndexOf("=") + 1, line.lastIndexOf("<")).trim());
                        entry.setSize(temp);
                    }
                }


            } else { // if the syscall says *** resumed, we should match it to the previous unfinished syscall -- matching via thread ID
                int syscall_end_index = syscall_index;
                while (line.charAt(syscall_end_index) != 32) {
                    syscall_end_index++;
                }
                entry.setSyscallName(line.substring(syscall_index, syscall_end_index));

                if (entry.getSyscallName().equals("recvfrom") || entry.getSyscallName().equals("writev")) {
                    int temp = Integer.valueOf(line.substring(line.lastIndexOf("=") + 1, line.lastIndexOf("<")).trim());
                    entry.setSize(temp);
                    if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                        entry.setFd(pendingSyscallTbl.get(entry.getThreadId()).getFd());
                        pendingSyscallTbl.remove(entry.getThreadId());
                        //System.err.format("Matched resume with unfinished syscall, fd %s size %d\n",entry.getFd(),entry.getSize());
                    } else {
                        System.err.println("Cannot find the matching unfinished syscall");
                    }
                }
            }

            if (line.contains(UNFINISH))
                continue;
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
            float duration = Float.valueOf(line.substring(line.lastIndexOf("<") + 1, line.lastIndexOf(">")));
            entry.setDuration(duration);

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
        StringBuilder top = new StringBuilder("");
        String time = "% time";
        String seconds = "seconds";
        String calls = "calls";
        String syscall = "syscall";

        //right side aligned
        System.err.format("%6s %11s %9s %16s\n", time, seconds, calls, syscall);

        System.err.println("------ ----------- --------- ----------------");

        float time_percent = 0;
        int count_per_syscall = 0;
        for (Map.Entry<String, List<SyscallEntry>> e : map.entrySet()) {
            float total_time_syscall = 0;
            for (SyscallEntry call : e.getValue()) {
                total_time_syscall += call.getDuration();
            }
            time_percent = 100 * total_time_syscall / sum_time;
            count_per_syscall = e.getValue().size();
            System.err.format("%5.2f %12.2f %9d %16s\n", time_percent, total_time_syscall, count_per_syscall, e.getKey());

            sort(e.getValue());
            for (int i = 0; i < (e.getValue().size() < 10 ? e.getValue().size() : 10); i++) {
                top.append(e.getKey() + " --- " + String.format("%.5f", e.getValue().get(i).getDuration()));
                top.append("\n");
            }


            if (e.getKey() == "recvfrom")

                top.append("\n");
        }


        System.err.format(" \n -------------------- \n FDs that send the most traffic to EMS \n -------------------- \n");
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
            System.err.println(ite.next());
        }


        System.err.format(" \n -------------------- \n FDs that get the most traffic from EMS \n -------------------- \n");
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
            System.err.println(ite.next());
        }

        System.err.format(" \n -------------------- \n Syscall response time top 10 \n -------------------- \n");
        System.err.println(top);
    }



    private void sort(List<SyscallEntry> syscallCollections) {
        Collections.sort(syscallCollections);

    }
}

class ReadWriteSizeContainer implements Comparable<ReadWriteSizeContainer> {
    int fd;
    int size;

    ReadWriteSizeContainer(int fd, int size) {
        this.fd = fd;
        this.size = size;
    }

    int getFd() {
        return fd;
    }

    void setFd(int fd) {
        this.fd = fd;
    }

    int getSize() {
        return size;
    }

    void setSize(int size) {
        this.size = size;
    }

    @Override
    public int compareTo(ReadWriteSizeContainer readWriteSizeContainer) {
        if (readWriteSizeContainer.getSize() < size)
            return 0;  //To change body of implemented methods use File | Settings | File Templates.
        else
            return 1;
    }

    @Override
    public String toString() {
        return fd + " -- " + size;
    }

    @Override
    public boolean equals(Object obj){
        if(obj == null)
            return false;
        if( ((ReadWriteSizeContainer)obj).getFd() == (this.fd))
            return true;
        else
            return false;
    }
}


