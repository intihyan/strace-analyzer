
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.XYDataset;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with IntelliJ IDEA.
 * User: yanlinfeng
 * Date: 1/11/15
 * Time: 10:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class EpollTracker {

    private static String inputFile = "d:/macy/epoll.log";
    SimpleDateFormat sdf = new SimpleDateFormat(
            "yyyy/MM/dd HH:mm:ss.SSS");

    List<SyscallEntry> epoll_calls = new ArrayList<SyscallEntry>();

     public static void main(String[] args) {
        EpollTracker et = new EpollTracker();
        et.openAndCheck();
        et.createScatterPlot();
    }

    private void openAndCheck() {


        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(inputFile));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        String line;

        try {
            assert br != null;
            long prev = 0;
            long execTime = 0;
            while ((line = br.readLine()) != null) {
                Pattern p = Pattern.compile("([0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9])");
                Matcher m = p.matcher(line);

                if (m.find()) {
                    execTime = sdf.parse("2015/06/18 " + m.group(1)).getTime();

                    if (prev != 0) {
                        System.out.format("%d \n", execTime - prev);
                        SyscallEntry call = new SyscallEntry();
                        call.setDuration(execTime - prev);
                        call.setCallTime(execTime);
                        epoll_calls.add(call);
                    }
                    prev = execTime;
                }
                /* if ( line.contains("resume") ){ // continue read next line
                    br.readLine();
                }  */
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

    }

    private void createScatterPlot() {

        JFreeChart chart = ChartFactory.createTimeSeriesChart("epoll_wait call time", "time", "Execution Duration", createDataset(epoll_calls));
        XYPlot plot = (XYPlot) chart.getPlot();
        DateAxis axis = (DateAxis) plot.getDomainAxis();
        axis.setDateFormatOverride(new SimpleDateFormat("HH:mm:ss"));

        ChartFrame frame = new ChartFrame("epoll_wait interval", chart);
        frame.pack();
        frame.setVisible(true);

    }

    private XYDataset createDataset(List<SyscallEntry> calls) {
        TimeSeriesCollection result = new TimeSeriesCollection();
        TimeSeries series = new TimeSeries("");

        for (SyscallEntry callEntry : calls) {
            series.addOrUpdate(new Millisecond(new Date(callEntry.getCallTime())),
                    callEntry.getDuration());


        }

        result.addSeries(series);
        return result;
    }

}
