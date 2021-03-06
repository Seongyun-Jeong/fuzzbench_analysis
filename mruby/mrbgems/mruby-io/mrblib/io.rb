##
# IO

class IOError < StandardError; end
class EOFError < IOError; end

class IO
  SEEK_SET = 0
  SEEK_CUR = 1
  SEEK_END = 2

  BUF_SIZE = 4096

  def self.open(*args, &block)
    io = self.new(*args)

    return io unless block

    begin
      yield io
    ensure
      begin
        io.close unless io.closed?
      rescue StandardError
      end
    end
  end

  def self.popen(command, mode = 'r', **opts, &block)
    if !self.respond_to?(:_popen)
      raise NotImplementedError, "popen is not supported on this platform"
    end
    io = self._popen(command, mode, **opts)
    return io unless block

    begin
      yield io
    ensure
      begin
        io.close unless io.closed?
      rescue IOError
        # nothing
      end
    end
  end

  def self.pipe(&block)
    if !self.respond_to?(:_pipe)
      raise NotImplementedError, "pipe is not supported on this platform"
    end
    if block
      begin
        r, w = IO._pipe
        yield r, w
      ensure
        r.close unless r.closed?
        w.close unless w.closed?
      end
    else
      IO._pipe
    end
  end

  def self.read(path, length=nil, offset=0, mode: "r")
    str = ""
    fd = -1
    io = nil
    begin
      if path[0] == "|"
        io = IO.popen(path[1..-1], mode)
      else
        fd = IO.sysopen(path, mode)
        io = IO.open(fd, mode)
      end
      io.seek(offset) if offset > 0
      str = io.read(length)
    ensure
      if io
        io.close
      elsif fd != -1
        IO._sysclose(fd)
      end
    end
    str
  end

  def flush
    # mruby-io always writes immediately (no output buffer).
    raise IOError, "closed stream" if self.closed?
    self
  end

  def hash
    # We must define IO#hash here because IO includes Enumerable and
    # Enumerable#hash will call IO#read...
    self.__id__
  end

  def write(string)
    str = string.is_a?(String) ? string : string.to_s
    return 0 if str.empty?
    unless @buf.empty?
      # reset real pos ignore buf
      seek(pos, SEEK_SET)
    end
    len = syswrite(str)
    len
  end

  def <<(str)
    write(str)
    self
  end

  def eof?
    _check_readable
    begin
      _read_buf
      return @buf.empty?
    rescue EOFError
      return true
    end
  end
  alias_method :eof, :eof?

  def pos
    raise IOError if closed?
    sysseek(0, SEEK_CUR) - @buf.bytesize
  end
  alias_method :tell, :pos

  def pos=(i)
    seek(i, SEEK_SET)
  end

  def rewind
    seek(0, SEEK_SET)
  end

  def seek(i, whence = SEEK_SET)
    raise IOError if closed?
    sysseek(i, whence)
    @buf = ''
    0
  end

  def _read_buf
    return @buf if @buf && @buf.bytesize > 0
    sysread(BUF_SIZE, @buf)
  end

  def ungetc(substr)
    raise TypeError.new "expect String, got #{substr.class}" unless substr.is_a?(String)
    if @buf.empty?
      @buf.replace(substr)
    else
      @buf[0,0] = substr
    end
    nil
  end

  def ungetbyte(c)
    if c.is_a? String
      c = c.getbyte(0)
    else
      c &= 0xff
    end
    s = " "
    s.setbyte(0,c)
    ungetc s
  end

  def read(length = nil, outbuf = "")
    unless length.nil?
      unless length.is_a? Integer
        raise TypeError.new "can't convert #{length.class} into Integer"
      end
      if length < 0
        raise ArgumentError.new "negative length: #{length} given"
      end
      if length == 0
        return ""   # easy case
      end
    end

    array = []
    while true
      begin
        _read_buf
      rescue EOFError
        array = nil if array.empty? and (not length.nil?) and length != 0
        break
      end

      if length
        consume = (length <= @buf.bytesize) ? length : @buf.bytesize
        array.push IO._bufread(@buf, consume)
        length -= consume
        break if length == 0
      else
        array.push @buf
        @buf = ''
      end
    end

    if array.nil?
      outbuf.replace("")
      nil
    else
      outbuf.replace(array.join)
    end
  end

  def readline(arg = "\n", limit = nil)
    case arg
    when String
      rs = arg
    when Integer
      rs = "\n"
      limit = arg
    else
      raise ArgumentError
    end

    if rs.nil?
      return read
    end

    if rs == ""
      rs = "\n\n"
    end

    array = []
    while true
      begin
        _read_buf
      rescue EOFError
        array = nil if array.empty?
        break
      end

      if limit && limit <= @buf.size
        array.push @buf[0, limit]
        @buf[0, limit] = ""
        break
      elsif idx = @buf.index(rs)
        len = idx + rs.size
        array.push @buf[0, len]
        @buf[0, len] = ""
        break
      else
        array.push @buf
        @buf = ''
      end
    end

    raise EOFError.new "end of file reached" if array.nil?

    array.join
  end

  def gets(*args)
    begin
      readline(*args)
    rescue EOFError
      nil
    end
  end

  def readchar
    _read_buf
    _readchar(@buf)
  end

  def getc
    begin
      readchar
    rescue EOFError
      nil
    end
  end

  def readbyte
    _read_buf
    IO._bufread(@buf, 1).getbyte(0)
  end

  def getbyte
    readbyte
  rescue EOFError
    nil
  end

  # 15.2.20.5.3
  def each(&block)
    return to_enum unless block

    while line = self.gets
      block.call(line)
    end
    self
  end

  # 15.2.20.5.4
  def each_byte(&block)
    return to_enum(:each_byte) unless block

    while byte = self.getbyte
      block.call(byte)
    end
    self
  end

  # 15.2.20.5.5
  alias each_line each

  def each_char(&block)
    return to_enum(:each_char) unless block

    while char = self.getc
      block.call(char)
    end
    self
  end

  def readlines
    ary = []
    while (line = gets)
      ary << line
    end
    ary
  end

  def puts(*args)
    i = 0
    len = args.size
    while i < len
      s = args[i]
      if s.kind_of?(Array)
        puts(*s)
      else
        s = s.to_s
        write s
        write "\n" if (s[-1] != "\n")
      end
      i += 1
    end
    write "\n" if len == 0
    nil
  end

  def print(*args)
    i = 0
    len = args.size
    while i < len
      write args[i].to_s
      i += 1
    end
  end

  def printf(*args)
    write sprintf(*args)
    nil
  end

  alias_method :to_i, :fileno
  alias_method :tty?, :isatty
end

STDIN  = IO.open(0, "r")
STDOUT = IO.open(1, "w")
STDERR = IO.open(2, "w")

$stdin  = STDIN
$stdout = STDOUT
$stderr = STDERR
