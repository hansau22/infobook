class Pool:
    """ 
    Infolib.Pool ist eine Klasse, die Indizes verwaltet.

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen, ist aber moeglich.
    """

    def __init__(self, max_num, start = None):
        """
        @param max_num: Maxium, das nicht ueberschritten wird
        @type max_num: int

        @param start: Erste zahl, die vergeben wird
        @type start: int

        @return: None
        """
        if (start == None) or not isinstance(start, int):
            self.cur = 0
        else:
            self.cur = start
            
        if (max_num == 0) or not isinstance(max_num, int):
            self.max_num = None
        else:
            self.max_num = max_num
            
        self.free = []


    
    def give_next(self):
        """
        Gibt den naechsten freien Index
        @return: int Index, False falls max_num ueberschritten werden wuerde
        """
        if (self.cur != self.max_num) or (self.max_num == None):
            ret = self.cur
            self.cur += 1
            return ret
        
        if len(self.free) < 1:
            return False

        return self.free.pop()


    
    def remove(self, num):
        """
        Entfernt ein Index, d.h. er kann wieder vergeben werden
        @param num: nummer, die frei wird
        @type num: int
        @return: None
        """
        if isinstance(num, int):
            self.free.append(num)