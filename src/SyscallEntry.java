public class SyscallEntry implements Comparable<SyscallEntry> {

    String syscallName;
    int fd;
    int size;
    int threadId;
    float duration;
    String statFileName;
    long callTime;

    public String getStatFileName() {
        return statFileName;
    }

    public void setStatFileName(String statFileName) {
        this.statFileName = statFileName;
    }

    public long getCallTime() {
        return callTime;
    }

    public void setCallTime(long callTime) {
        this.callTime = callTime;
    }

    public int getFd() {
        return fd;
    }

    public void setFd(int fd) {
        this.fd = fd;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public String getSyscallName() {
        return syscallName;
    }

    public void setSyscallName(String syscallName) {
        this.syscallName = syscallName;
    }

    public int getThreadId() {
        return threadId;
    }

    public void setThreadId(int threadId) {
        this.threadId = threadId;
    }

    public float getDuration() {
        return duration;
    }

    public void setDuration(float duration) {
        this.duration = duration;
    }

    @Override
    public int compareTo(SyscallEntry syscallEntry) {
        if (this.duration < syscallEntry.getDuration())
            return 1;  //To change body of implemented methods use File | Settings | File Templates.
        else if (this.duration > syscallEntry.getDuration())
            return -1;
        else
            return 0;
    }

    public String toString() {
        return String.format("ThreadID: %s  SyscallName: %s", this.threadId, this.syscallName);
    }
}
