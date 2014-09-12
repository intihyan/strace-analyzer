import com.tibco.tibjms.admin.ServerInfo;
import com.tibco.tibjms.admin.TibjmsAdmin;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;


public class InOutBoundRateChart {


    TibjmsAdmin admin = null;
    ServerInfo serverInfo = null;


    public static void main(String[] args){
        InOutBoundRateChart ibrc = new InOutBoundRateChart();
        ibrc.draw( null, "Inbound Rate");
    }

    private void draw(String applicationTitle, String chartTitle) {

        // based on the dataset we create the chart
        try {
            JFreeChart chart = ChartFactory.createXYLineChart(chartTitle, "Category", "Score", createDataset(), PlotOrientation.VERTICAL, true, true, false);
            ChartFrame frame = new ChartFrame("EMS InBound Rate", chart);
            frame.pack();
            frame.setVisible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    private XYDataset createDataset() throws Exception {

        final XYSeries inRate = new XYSeries("Inbound Rate");
        final XYSeries outRate = new XYSeries("Outbound Rate");
        admin = new TibjmsAdmin("tcp://10.107.134.230:7222", "admin", "");

        int start = 1;
        while (start <= 300) {
            serverInfo = admin.getInfo();
            //System.out.format("Inbound:%5d Outbound:%5d  size:%10d MB\n", serverInfo.getInboundMessageRate(), serverInfo.getOutboundMessageRate(), Math.round(serverInfo.getAsyncDBSize() / 1048576));
            inRate.add(start, serverInfo.getInboundMessageRate());
            outRate.add(start, serverInfo.getOutboundMessageRate());
            start++;
            Thread.sleep(1000);
        }


        final XYSeriesCollection dataset = new XYSeriesCollection();
        dataset.addSeries(inRate);
        dataset.addSeries(outRate);

        return dataset;

    }

}
