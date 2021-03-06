import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.util.ShapeUtilities;


public class WriteSizeAnalyzer {

    private static int LINEFEED = 10;
    private static String SYSCALL_FUTEX = "futex";
    private static String SYSCALL_CLOCK = "clock_gettime";
    private static String RESUME = "resumed";
    private static String UNFINISH = "unfinished";
    String fileName = "/Users/yanlinfeng/chrome/strace_ems.log";
    float sum_time = 0;
    MappedByteBuffer buffer;
    HashMap<Integer, SyscallEntry> pendingSyscallTbl = new HashMap<Integer, SyscallEntry>();
    HashMap<Integer, List<SyscallEntry>> writeTbl = new HashMap<Integer, List<SyscallEntry>>();
    
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSSSSS");


    public static void main(String[] args) {
        long begin = System.currentTimeMillis();
        WriteSizeAnalyzer sa = new WriteSizeAnalyzer();

        sa.readFileNIO();
        sa.calcDistribution();
        //sa.createScatterPlot();
        
        sa.writeCsv();
        System.err.format("\ntotal memory used %.2f M\n", (float) (Runtime.getRuntime().totalMemory() / (1024 * 1024)));

        System.err.format("\ntotal time spent %.0f Seconds", (float) ((System.currentTimeMillis() - begin) / 1000));
    }

    private void writeCsv(){
    	double base = 0;
    	int count = 0;
    	 DecimalFormat df = new DecimalFormat("#.##########");
        for(Map.Entry<Integer, List<SyscallEntry>> e :  writeTbl.entrySet())
        {
        	base = 0;
        	count = 0;
        	try {
    			BufferedWriter bw = new BufferedWriter(new FileWriter("/Users/yanlinfeng/sr/506930/1120/" + e.getKey() + ".strace_ems.log"));
    			for (SyscallEntry call : e.getValue()){
    				if(count == 0 )
    					base = call.getCallTime();
    				//bw.write( call.getCallTime() - base + "," + call.getSize());
    				bw.write( String.format("%10f ,%7d \n", call.getDuration() * 1000, call.getSize()));
    				//bw.write(  df.format(call.getDuration() * 1000 * 1000/ call.getSize()) );
    				count++;
    		
    			}
    			bw.close();
    		} catch (IOException ex) {
    			// TODO Auto-generated catch block
    			ex.printStackTrace();
    		}
        }
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
            temp = temp.substring(0, temp.length() - 3);
            String start_time = "2014/05/02 " + temp;
            //SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSSSSS");
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
                    entry.setFd(fd);
                    


                    if (line.contains(UNFINISH)) {
                        if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                            System.err.println("Error : " + line);
                        } else {
                            pendingSyscallTbl.put(entry.getThreadId(), entry);
                        }
                    }
                } else
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
                 
                if (pendingSyscallTbl.containsKey(entry.getThreadId())) {
                	
                    entry.setFd(pendingSyscallTbl.get(entry.getThreadId()).getFd());
                    pendingSyscallTbl.remove(entry.getThreadId());
                    //System.err.format("Matched resume with unfinished syscall, fd %s size %d\n",entry.getFd(),entry.getSize());
                  
                } else {
                    System.err.println("Cannot find the matching unfinished syscall");
                }
            }
            
            if ( entry.getFd() <  6 )
        		continue;

            if (line.contains(UNFINISH))
                continue;
            
            entry.setSize(Integer.valueOf(line.substring(line.lastIndexOf("=") + 1, line.lastIndexOf("<")).trim()));
            
            float duration = Float.valueOf(line.substring(line.lastIndexOf("<") + 1, line.lastIndexOf(">")));
            entry.setDuration(duration);


            if (entry.getFd() == 0)
                System.err.println(line);
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
        double base = 0;
        for (SyscallEntry callEntry : calls) {
            if (count == 0) {
                base = callEntry.getCallTime();
                System.err.format("%f \n", base);
                series.add(0, callEntry.getSize() );
            } else
                series.add(callEntry.getCallTime() - base, callEntry.getSize());
            count++;
        }
        result.addSeries(series);
        return result;
    }

    private void createScatterPlot() {

        for (Map.Entry<Integer, List<SyscallEntry>> e : writeTbl.entrySet()) {
            JFreeChart chart = ChartFactory.createScatterPlot(
                    "Scatter Plot", // chart title
                    "X", // x axis label
                    "write() size", // y axis label
                    createDataset(e.getValue()), // data  ***-----PROBLEM------***
                    PlotOrientation.VERTICAL,
                    true, // include legend
                    true, // tooltips
                    false // urls
            );
            XYPlot xyPlot = chart.getXYPlot();
            xyPlot.getRenderer().setSeriesShape(0, ShapeUtilities.createDiagonalCross(3, 1));
            ValueAxis rangeAxis = xyPlot.getRangeAxis();
 
            rangeAxis.setRange(0.0, 10000.0);
             
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

