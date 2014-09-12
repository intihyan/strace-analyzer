
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