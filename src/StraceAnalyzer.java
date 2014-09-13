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

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

public class StraceAnalyzer {

	String outputDir = "D:/tmp/";
	int fileNameIndex = 0;
	private static int LINEFEED = 10;
	private static String SYSCALL_FUTEX = "futex";
	private static String SYSCALL_CLOCK = "clock_gettime";
	private static String SYSCALL_RESTART = "restart_syscall";
	private static String SYSCALL_LSEEK = "lseek";
	private static String SYSCALL_FDATASYNC = "fdatasync";
	private static String SYSCALL_FCNTL = "fcntl";
	private static String SYSCALL_EPOLLWAIT = "epoll_wait";
	private static String SYSCALL_EPOLLCTL = "epoll_ctl";
	private static String SYSCALL_SOCKET = "socket";
	private static String SYSCALL_ACCEPT = "accept";
	private static String SYSCALL_SETSOCKETOPT = "setsockopt";
	private static String SYSCALL_CONNECT = "connect";
	private static String SYSCALL_SELECT = " select";
	private static String SYSCALL_CLOSE = "close";
	private static String SYSCALL_SENDTO = "sendto";
	private static String SYSCALL_SHUTDOWN = "shutdown";
	private static String EAGAIN = "EAGAIN";
	private static String ETIMEDOUT = "ETIMEDOUT";
	private static String RESUME = "resumed";
	private static String UNFINISH = "unfinished";
	String fileName = "c:/strace.log";
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

	public static void main(String[] args) {
		long begin = System.currentTimeMillis();
		StraceAnalyzer sa = new StraceAnalyzer();

		sa.readFileNIO();
		sa.calcDistribution();
		sa.prettyPrint();

		sa.createScatterPlotWrite();
		sa.createScatterPlotStat();
		sa.createScatterPlotRead();
		sa.createScatterPlotLseek();
		sa.createScatterPlotFsync();
		
		/*
		System.err.format("\ntotal memory used %.2f M\n", (float) (Runtime
				.getRuntime().totalMemory() / (1024 * 1024)));
		System.err.format("\ntotal time spent %.0f Seconds",
				(float) ((System.currentTimeMillis() - begin) / 1000));
		*/
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
			if (line.indexOf(SYSCALL_RESTART) != -1
					|| line.indexOf(SYSCALL_FUTEX) != -1
					|| line.indexOf(SYSCALL_CLOCK) != -1
					|| line.indexOf(SYSCALL_EPOLLWAIT) != -1
					|| line.indexOf(SYSCALL_EPOLLCTL) != -1
					|| line.indexOf(SYSCALL_FCNTL) != -1
					|| line.indexOf(SYSCALL_SOCKET) != -1
					|| line.indexOf(SYSCALL_CONNECT) != -1
					|| line.indexOf(SYSCALL_ACCEPT) != -1
					|| line.indexOf(SYSCALL_SELECT) != -1
					|| line.indexOf(SYSCALL_CLOSE) != -1
					|| line.indexOf(SYSCALL_SENDTO) != -1
					|| line.indexOf(SYSCALL_SHUTDOWN) != -1
					|| line.indexOf(SYSCALL_SETSOCKETOPT) != -1
					|| line.indexOf(EAGAIN) != -1
					|| line.indexOf(ETIMEDOUT) != -1 )
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

			String temp = line.substring(line.indexOf(32), syscall_index)
					.trim();
			temp = temp.substring(0, temp.length() - 3);
			String start_time = "2014/05/02 " + temp;
			SimpleDateFormat sdf = new SimpleDateFormat(
					"yyyy/MM/dd HH:mm:ss.SSSSSS");
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
				
				if (entry.getSyscallName().equals("fdatasync")){
					
					if( line.contains(UNFINISH) ){
						int syscall_fd_index = syscall_end_index;
						while (line.charAt(syscall_fd_index) != '<') {
							syscall_fd_index++;
						}
						int fd = Integer.valueOf(line.substring(
								syscall_end_index + 1, syscall_fd_index - 1));
	
						entry.setFd(fd);
					} else {
						entry.setFd(Integer.valueOf(line.substring(syscall_end_index+1, syscall_end_index+2)));
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
	 * We print the following information: - System call distribution by syscall
	 * names and time usage percentage - Top 10 time consuming syscall grouped
	 * by each system call name - Top 10 read/write total size of
	 * recvfrom()/writev() syscall, this typically can pinpoint the file
	 * descriptor which are generating traffic, it can then be used together
	 * with lsof output to find out the client IP address
	 */
	private void prettyPrint() {
		StringBuilder top = new StringBuilder("");
		String time = "% time";
		String seconds = "seconds";
		String calls = "calls";
		String syscall = "syscall";

		// right side aligned
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
			System.err.format("%5.2f %12.2f %9d %16s\n", time_percent,
					total_time_syscall, count_per_syscall, e.getKey());

			sort(e.getValue());
			for (int i = 0; i < (e.getValue().size() < 10 ? e.getValue().size()
					: 10); i++) {
				top.append(e.getKey()
						+ " --- "
						+ String.format("%.7f", e.getValue().get(i)
								.getDuration()));
				top.append("\n");
			}

			if (e.getKey() == "recvfrom")

				top.append("\n");
		}

		System.err
				.format(" \n -------------------- \n FDs that send the most traffic to EMS \n -------------------- \n");
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

		System.err
				.format(" \n -------------------- \n FDs that get the most traffic from EMS \n -------------------- \n");
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

		System.err
				.format(" \n -------------------- \n Syscall response time top 10 \n -------------------- \n");
		System.err.println(top);
	}

	private XYDataset createDatasetWrite(Set<SyscallEntry> calls) {

		XYSeriesCollection result = new XYSeriesCollection();
		XYSeries series = new XYSeries("Random");
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

	private void createScatterPlotWrite() {

		for (Map.Entry<Integer, Set<SyscallEntry>> e : writeTbl.entrySet()) {
			System.out.format("Number of writes in this FD %d: %d \n",
					e.getKey(), e.getValue().size());

			JFreeChart chart = ChartFactory.createScatterPlot(
					"FD:" + e.getKey() + " write() response time", // chart
																	// title
					"X", // x axis label
					"Response Time in millisecond", // y axis label
					createDatasetWrite(e.getValue()), // data
														// ***-----PROBLEM------***
					PlotOrientation.VERTICAL, true, // include legend
					true, // tooltips
					false // urls
					);

			// create and display a frame...
			/*
			 * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */

			try {
				String fileName = outputDir + fileNameIndex++ + "_write.jpg";
				ChartUtilities.saveChartAsJPEG(new File(fileName), chart, 1024,
						768, null);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	private XYDataset createDatasetRead(Set<SyscallEntry> calls) {

		XYSeriesCollection result = new XYSeriesCollection();
		XYSeries series = new XYSeries("Random");
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

	private void createScatterPlotRead() {

		for (Map.Entry<Integer, Set<SyscallEntry>> e : readTbl.entrySet()) {
			System.out.format("Number of read in this FD %d: %d \n",
					e.getKey(), e.getValue().size());

			JFreeChart chart = ChartFactory.createScatterPlot(
					"FD:" + e.getKey() + " read() response time", // chart title
					"X", // x axis label
					"Response Time in millisecond", // y axis label
					createDatasetRead(e.getValue()), // data
														// ***-----PROBLEM------***
					PlotOrientation.VERTICAL, true, // include legend
					true, // tooltips
					false // urls
					);

			// create and display a frame...
			/*
			 * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */

			try {
				String fileName = outputDir + fileNameIndex++ + "_read.jpg";
				ChartUtilities.saveChartAsJPEG(new File(fileName), chart, 1024,
						768, null);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}private XYDataset createDatasetLseek(Set<SyscallEntry> calls) {

		XYSeriesCollection result = new XYSeriesCollection();
		XYSeries series = new XYSeries("Random");
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

	private void createScatterPlotLseek() {

		for (Map.Entry<Integer, Set<SyscallEntry>> e : lseekTbl.entrySet()) {
			System.out.format("Number of lseek in this FD %d: %d \n",
					e.getKey(), e.getValue().size());

			JFreeChart chart = ChartFactory.createScatterPlot(
					"FD:" + e.getKey() + " lseek() response time", // chart title
					"X", // x axis label
					"Response Time in millisecond", // y axis label
					createDatasetLseek(e.getValue()), // data
														// ***-----PROBLEM------***
					PlotOrientation.VERTICAL, true, // include legend
					true, // tooltips
					false // urls
					);

			// create and display a frame...
			/*
			 * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */

			try {
				String fileName = outputDir + fileNameIndex++ + "_lseek.jpg";
				ChartUtilities.saveChartAsJPEG(new File(fileName), chart, 1024,
						768, null);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}
	
	private XYDataset createDatasetFsync(Set<SyscallEntry> calls) {

		XYSeriesCollection result = new XYSeriesCollection();
		XYSeries series = new XYSeries("Random");
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

	private void createScatterPlotFsync() {

		for (Map.Entry<Integer, Set<SyscallEntry>> e : fsyncTbl.entrySet()) {
			System.out.format("Number of fdatasync in this FD %d: %d \n",
					e.getKey(), e.getValue().size());

			JFreeChart chart = ChartFactory.createScatterPlot(
					"FD:" + e.getKey() + " fdatasync() response time", // chart title
					"X", // x axis label
					"Response Time in millisecond", // y axis label
					createDatasetFsync(e.getValue()), // data
														// ***-----PROBLEM------***
					PlotOrientation.VERTICAL, true, // include legend
					true, // tooltips
					false // urls
					);

			// create and display a frame...
			/*
			 * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */

			try {
				String fileName = outputDir + fileNameIndex++ + "_fdatasync.jpg";
				ChartUtilities.saveChartAsJPEG(new File(fileName), chart, 1024,
						768, null);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}

	private XYDataset createDatasetStat(Set<SyscallEntry> calls) {
		XYSeriesCollection result = new XYSeriesCollection();
		XYSeries series = new XYSeries("Random");
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
			JFreeChart chart = ChartFactory.createScatterPlot(e.getKey()
					+ " stat() response", // chart
					// title
					"X", // x axis label
					"Response Time in millisecond", // y axis label
					createDatasetStat(e.getValue()), // data
														// ***-----PROBLEM------***
					PlotOrientation.VERTICAL, true, // include legend
					true, // tooltips
					false // urls
					);

			// create and display a frame...
			/*
			 * ChartFrame frame = new ChartFrame(e.getKey().toString(), chart);
			 * frame.pack(); frame.setVisible(true);
			 */
			try {
				String fileName = outputDir + fileNameIndex++ + "_stat.jpg";
				ChartUtilities.saveChartAsJPEG(new File(fileName), chart, 1024,
						768, null);
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
